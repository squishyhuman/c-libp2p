
#include <memory.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "libp2p/net/stream.h"
#include "libp2p/os/timespec.h"
#include "libp2p/yamux/session.h"
#include "libp2p/yamux/stream.h"
#include "libp2p/yamux/yamux.h"
#include "libp2p/utils/logger.h"

static struct yamux_config dcfg = YAMUX_DEFAULT_CONFIG;

/***
 * Create a new yamux session
 * @param config the configuration
 * @param sock the socket
 * @param type session type (yamux_session_server or yamux_session_client)
 * @param userdata user data
 * @returns the yamux_session struct
 */
struct yamux_session* yamux_session_new(struct yamux_config* config, struct Stream* parent_stream, enum yamux_session_type type, void* userdata)
{
    if (!parent_stream)
        return NULL;

    if (!config)
        config = &dcfg;

    size_t ab = config->accept_backlog;

    struct yamux_session_stream* streams =
        (struct yamux_session_stream*)malloc(sizeof(struct yamux_session_stream) * ab);

    for (size_t i = 0; i < ab; ++i)
        streams[i].alive = 0;

    struct yamux_session* sess = (struct yamux_session*)malloc(sizeof(struct yamux_session));
    if (sess != NULL) {
        sess->config = config;
        sess->type   = type;
        sess->parent_stream = parent_stream;
        sess->closed = 0;
        sess->nextid = 1 + (type == yamux_session_server);
        sess->num_streams = 0;
        sess->cap_streams = 0;
        sess->streams = streams;
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 0;
        sess->since_ping = ts;
        sess->get_str_ud_fn = NULL;
        sess->ping_fn       = NULL;
        sess->pong_fn       = NULL;
        sess->go_away_fn    = NULL;
        sess->free_fn       = NULL;
        sess->userdata = userdata;
    }

    return sess;
}

void yamux_session_free(struct yamux_session* session)
{
    if (!session)
        return;

    if (!session->closed)
        yamux_session_close(session, yamux_error_normal);

    if (session->free_fn)
        session->free_fn(session);

    for (size_t i = 0; i < session->cap_streams; ++i)
        if (session->streams[i].alive)
            yamux_stream_free(session->streams[i].stream);

    free(session->streams);
    free(session);
}

/***
 * Close a yamux session
 * @param session the yamux_session to close
 * @param err why we're closing
 */
ssize_t yamux_session_close(struct yamux_session* session, enum yamux_error err)
{
    if (!session)
        return -EINVAL;
    if (session->closed)
        return 0;

    struct yamux_frame f = (struct yamux_frame){
        .version  = YAMUX_VERSION,
        .type     = yamux_frame_go_away,
        .flags    = 0,
        .streamid = YAMUX_STREAMID_SESSION,
        .length   = (uint32_t)err
    };

    session->closed = 1;

    struct StreamMessage outgoing;
    outgoing.data = (uint8_t*)&f;
    outgoing.data_size = sizeof(struct yamux_frame);

    if (!session->parent_stream->write(session->parent_stream->stream_context, &outgoing))
    		return 0;
    return outgoing.data_size;
}

/***
 * Ping
 * @param session the session to ping
 * @param value the value to send
 * @param pong true(1) if we should send the ack, false(0) if we should send the syn (who's side are we on?)
 * @returns number of bytes sent
 */
ssize_t yamux_session_ping(struct yamux_session* session, uint32_t value, int pong)
{
    if (!session || session->closed)
        return -EINVAL;

    struct yamux_frame f = (struct yamux_frame){
        .version  = YAMUX_VERSION,
        .type     = yamux_frame_ping,
        .flags    = pong ? yamux_frame_ack : yamux_frame_syn,
        .streamid = YAMUX_STREAMID_SESSION,
        .length   = value
    };

    if (!timespec_get(&session->since_ping, TIME_UTC))
        return -EACCES;

    struct StreamMessage outgoing;
    outgoing.data = (uint8_t*)&f;
    outgoing.data_size = sizeof(struct yamux_frame);
    if (!session->parent_stream->write(session->parent_stream->stream_context, &outgoing))
    		return 0;
    return outgoing.data_size;
}

/**
 * Decode an incoming message
 * @param context the YamuxContext or YamuxChannelContext
 * @param incoming the incoming bytes
 * @param incoming_size the size of the incoming bytes
 * @param return_message the results (usually the stuff after the frame)
 * @returns 0 on success, negative number on error
 */
int yamux_decode(void* context, const uint8_t* incoming, size_t incoming_size, struct StreamMessage** return_message) {

	// retrieve the yamux context
	struct yamux_session* yamux_session = NULL;
	struct YamuxContext* yamuxContext = NULL;
	if (context == NULL)
		return 0;
	if ( ((char*)context)[0] == YAMUX_CONTEXT) {
		yamuxContext = (struct YamuxContext*)context;
		yamux_session = yamuxContext->session;
	} else if ( ((char*)context)[0] == YAMUX_CHANNEL_CONTEXT) {
		struct YamuxChannelContext* channelContext = (struct YamuxChannelContext*)context;
		yamuxContext = channelContext->yamux_context;
		yamux_session = channelContext->yamux_context->session;
	}
	// decode frame
	struct yamux_frame f;

	if (incoming_size < sizeof(struct yamux_frame)) {
		return 0;
	}
	memcpy((void*)&f, incoming, sizeof(struct yamux_frame));

    decode_frame(&f);

    // check yamux version
    if (f.version != YAMUX_VERSION)
        return 0;

    if (!f.streamid) // we're not dealing with a stream, we're dealing with something at the yamux protocol level
        switch (f.type)
        {
            case yamux_frame_ping: // ping
                if (f.flags & yamux_frame_syn)
                {
                    yamux_session_ping(yamux_session, f.length, 1);

                    if (yamux_session->ping_fn)
                        yamux_session->ping_fn(yamux_session, f.length);
                }
                else if ((f.flags & yamux_frame_ack) && yamux_session->pong_fn)
                {
                    struct timespec now, dt, last = yamux_session->since_ping;
                    if (!timespec_get(&now, TIME_UTC))
                        return -EACCES;

                    dt.tv_sec = now.tv_sec - last.tv_sec;
                    if (now.tv_nsec < last.tv_nsec)
                    {
                        dt.tv_sec--;
                        dt.tv_nsec = last.tv_nsec - now.tv_nsec;
                    }
                    else
                        dt.tv_nsec = now.tv_nsec - last.tv_nsec;

                    yamux_session->pong_fn(yamux_session, f.length, dt);
                }
                else
                    return -EPROTO;
                break;
            case yamux_frame_go_away: // go away (hanging up)
                yamux_session->closed = 1;
                if (yamux_session->go_away_fn)
                    yamux_session->go_away_fn(yamux_session, (enum yamux_error)f.length);
                break;
            default:
                return -EPROTO;
        }
    else { // we're handling a stream, not something at the yamux protocol level
        for (size_t i = 0; i < yamux_session->cap_streams; ++i)
        {
            struct yamux_session_stream* ss = &yamux_session->streams[i];
            struct yamux_stream* s = ss->stream;

            if (!ss->alive || s->state == yamux_stream_closed) // skip dead or closed streams
                continue;

            if (s->id == f.streamid) // we have a match between the stored stream and the current stream
            {
                if (f.flags & yamux_frame_rst)
                {
                	// close the stream
                    s->state = yamux_stream_closed;

                    if (s->rst_fn)
                        s->rst_fn(s);
                }
                else if (f.flags & yamux_frame_fin)
                {
                    // local stream didn't initiate FIN
                    if (s->state != yamux_stream_closing)
                        yamux_stream_close(context);

                    s->state = yamux_stream_closed;

                    if (s->fin_fn)
                        s->fin_fn(s);
                }
                else if (f.flags & yamux_frame_ack)
                {
                	// acknowldegement
                    if (s->state != yamux_stream_syn_sent)
                        return -EPROTO;

                    s->state = yamux_stream_est;
                }
                else if (f.flags)
                    return -EPROTO;

                int sz = sizeof(struct yamux_frame);
                ssize_t re = yamux_stream_process(s, &f, &incoming[sz], incoming_size - sz);
                return (re < 0) ? re : (re + incoming_size);
            }
        }

        // This stream is not in my list of streams.
        // It must not exist yet, so let's try to make it
        if (f.flags & yamux_frame_syn)
        {
            struct StreamMessage* msg = libp2p_stream_message_new();

           	if (incoming_size > sizeof(struct yamux_frame)) {
           		msg->data_size = incoming_size - sizeof(struct yamux_frame);
           		msg->data = malloc(msg->data_size);
           		memcpy(msg->data, &incoming[sizeof(struct yamux_frame)], msg->data_size);
           	}

           	// if we didn't initiate it, add this new channel (odd stream id is from client, even is from server)
           	if ( (f.streamid % 2 == 0 && yamuxContext->am_server) || (f.streamid % 2 == 1 && yamuxContext->am_server) ) {
           		struct Stream* yamuxChannelStream = yamux_channel_new(yamuxContext, f.streamid, msg);
           		if (yamuxChannelStream == NULL) {
           			libp2p_logger_error("yamux", "session->yamux_decode: Unable to create new yamux channel for stream id %d.\n", f.streamid);
           			return -EPROTO;
           		}
           		struct YamuxChannelContext* channelContext = (struct YamuxChannelContext*)yamuxChannelStream->stream_context;

           		if (yamux_session->new_stream_fn) {
           			libp2p_logger_debug("yamux", "session->yamux_decode: Calling new_stream_fn.\n");
           			yamux_session->new_stream_fn(yamuxContext, yamuxContext->stream, msg);
           		}

           		channelContext->state = yamux_stream_syn_recv;
           	}
            *return_message = msg;
        }
        else
            return -EPROTO;
    }
	return 0;
}

