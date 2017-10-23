
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

static struct yamux_config dcfg = YAMUX_DEFAULT_CONFIG;

/***
 * Create a new yamux session
 * @param config the configuration
 * @param sock the socket
 * @param type session type (yamux_session_server or yamux_session_client)
 * @param userdata user data
 * @returns the yamux_session struct
 */
struct yamux_session* yamux_session_new(struct yamux_config* config, struct SessionContext* session_context, enum yamux_session_type type, void* userdata)
{
    if (!session_context)
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
        sess->session_context = session_context;
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

    if (!session->session_context->default_stream->write(session->session_context, &outgoing))
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
    if (!session->session_context->default_stream->write(session->session_context, &outgoing))
    		return 0;
    return outgoing.data_size;
}

/**
 * Decode an incoming message
 * @param incoming the incoming bytes
 * @param incoming_size the size of the incoming bytes
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_decode(struct yamux_session* session, const uint8_t* incoming, size_t incoming_size) {
	// decode frame
	struct yamux_frame f;

	if (incoming_size < sizeof(struct yamux_frame)) {
		return 0;
	}
    decode_frame(&f);

    // check yamux version
    if (f.version != YAMUX_VERSION)
        return 0;

    if (!f.streamid) // we're not dealing with a stream
        switch (f.type)
        {
            case yamux_frame_ping: // ping
                if (f.flags & yamux_frame_syn)
                {
                    yamux_session_ping(session, f.length, 1);

                    if (session->ping_fn)
                        session->ping_fn(session, f.length);
                }
                else if ((f.flags & yamux_frame_ack) && session->pong_fn)
                {
                    struct timespec now, dt, last = session->since_ping;
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

                    session->pong_fn(session, f.length, dt);
                }
                else
                    return -EPROTO;
                break;
            case yamux_frame_go_away: // go away (hanging up)
                session->closed = 1;
                if (session->go_away_fn)
                    session->go_away_fn(session, (enum yamux_error)f.length);
                break;
            default:
                return -EPROTO;
        }
    else { // we're handling a stream
        for (size_t i = 0; i < session->cap_streams; ++i)
        {
            struct yamux_session_stream* ss = &session->streams[i];
            struct yamux_stream* s = ss->stream;

            if (!ss->alive || s->state == yamux_stream_closed)
                continue;

            if (s->id == f.streamid)
            {
                if (f.flags & yamux_frame_rst)
                {
                    s->state = yamux_stream_closed;

                    if (s->rst_fn)
                        s->rst_fn(s);
                }
                else if (f.flags & yamux_frame_fin)
                {
                    // local stream didn't initiate FIN
                    if (s->state != yamux_stream_closing)
                        yamux_stream_close(s);

                    s->state = yamux_stream_closed;

                    if (s->fin_fn)
                        s->fin_fn(s);
                }
                else if (f.flags & yamux_frame_ack)
                {
                    if (s->state != yamux_stream_syn_sent)
                        return -EPROTO;

                    s->state = yamux_stream_est;
                }
                else if (f.flags)
                    return -EPROTO;

                int sz = sizeof(struct yamux_frame);
                ssize_t re = yamux_stream_process(s, &f, &incoming[sz], incoming_size - sz, session->session_context);
                return (re < 0) ? re : (re + incoming_size);
            }
        }

        // stream doesn't exist yet
        if (f.flags & yamux_frame_syn)
        {
            void* ud = NULL;

            if (session->get_str_ud_fn)
                ud = session->get_str_ud_fn(session, f.streamid);

            struct yamux_stream* st = yamux_stream_new(session, f.streamid, ud);

            if (session->new_stream_fn)
                session->new_stream_fn(session, st);

            st->state = yamux_stream_syn_recv;
        }
        else
            return -EPROTO;
    }
	return 0;
}

