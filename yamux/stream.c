
#include <errno.h>
#include <memory.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>

#include "libp2p/conn/session.h"
#include "libp2p/net/stream.h"
#include "libp2p/yamux/frame.h"
#include "libp2p/yamux/stream.h"

#define MIN(x,y) (y^((x^y)&-(x<y)))
#define MAX(x,y) (x^((x^y)&-(x<y)))


/***
 * Create a new stream
 * @param session the session
 * @param id the id (0 to set it to the next id)
 * @Param userdata the user data
 * @returns a new yamux_stream struct
 */
struct yamux_stream* yamux_stream_new(struct yamux_session* session, yamux_streamid id, void* userdata)
{
    if (!session)
        return NULL;

    if (!id)
    {
        id = session->nextid;
        session->nextid += 2;
    }

    struct yamux_stream* st = NULL;
    struct yamux_session_stream* ss;

    if (session->num_streams != session->cap_streams)
        for (size_t i = 0; i < session->cap_streams; ++i)
        {
            ss = &session->streams[i];

            if (!ss->alive)
            {
                st = ss->stream;
                ss->alive = 1;
                goto FOUND;
            }
        }

    if (session->cap_streams == session->config->accept_backlog)
        return NULL;

    ss = &session->streams[session->cap_streams];

    if (ss->alive)
        return NULL;

    session->cap_streams++;

    ss->alive = 1;
    st = ss->stream = malloc(sizeof(struct yamux_stream));

FOUND:;

    struct yamux_stream nst = (struct yamux_stream){
        .id          = id,
        .session     = session,
        .state       = yamux_stream_inited,
        .window_size = YAMUX_DEFAULT_WINDOW,

        .read_fn = NULL,
        .fin_fn  = NULL,
        .rst_fn  = NULL,

        .userdata = userdata
    };
    *st = nst;

    return st;
}

/**
 * Write a frame to the network
 * @param yamux_stream the stream context
 * @param f the frame
 */
int yamux_write_frame(struct YamuxContext* ctx, struct yamux_frame* f) {
	encode_frame(f);
	struct StreamMessage outgoing;
	outgoing.data = (uint8_t*)f;
	outgoing.data_size = sizeof(struct yamux_frame);
	if (!ctx->stream->write(ctx->stream->stream_context, &outgoing))
		return 0;
	return outgoing.data_size;
}

/***
 * Initialize a stream between 2 peers
 * @param stream the stream to initialize
 * @returns the number of bytes sent
 */
ssize_t yamux_stream_init(struct YamuxChannelContext* channel_ctx)
{
    if (!channel_ctx || channel_ctx->state != yamux_stream_inited || channel_ctx->closed) {
        return -EINVAL;
    }

    struct yamux_frame f = (struct yamux_frame){
        .version  = YAMUX_VERSION,
        .type     = yamux_frame_window_update,
        .flags    = yamux_frame_syn,
        .streamid = channel_ctx->channel,
        .length   = 0
    };

    channel_ctx->state = yamux_stream_syn_sent;

    return yamux_write_frame(channel_ctx->yamux_context->stream->stream_context, &f);
}

/***
 * Close a stream
 * @param stream the stream
 * @returns the number of bytes sent
 */
ssize_t yamux_stream_close(struct YamuxChannelContext* channel_ctx)
{
    if (!channel_ctx || channel_ctx->state != yamux_stream_est || channel_ctx->closed)
        return -EINVAL;

    struct yamux_frame f = (struct yamux_frame){
        .version  = YAMUX_VERSION,
        .type     = yamux_frame_window_update,
        .flags    = yamux_frame_fin,
        .streamid = channel_ctx->channel,
        .length   = 0
    };

    channel_ctx->state = yamux_stream_closing;

    return yamux_write_frame(channel_ctx->yamux_context->stream->stream_context, &f);
}

/**
 * Reset the stream
 * @param stream the stream
 * @returns the number of bytes sent
 */
ssize_t yamux_stream_reset(struct YamuxChannelContext* channel_ctx)
{
    if (!channel_ctx || channel_ctx->closed)
        return -EINVAL;

    struct yamux_frame f = (struct yamux_frame){
        .version  = YAMUX_VERSION,
        .type     = yamux_frame_window_update,
        .flags    = yamux_frame_rst,
        .streamid = channel_ctx->channel,
        .length   = 0
    };

    channel_ctx->state = yamux_stream_closed;

    return yamux_write_frame(channel_ctx->yamux_context->stream->stream_context, &f);
}

static enum yamux_frame_flags get_flags(struct YamuxChannelContext* ctx)
{
    switch (ctx->state)
    {
        case yamux_stream_inited:
            ctx->state = yamux_stream_syn_sent;
            return yamux_frame_syn;
        case yamux_stream_syn_recv:
            ctx->state = yamux_stream_est;
            return yamux_frame_ack;
        default:
            return 0;
    }
}

/**
 * update the window size
 * @param stream the stream
 * @param delta the new window size
 * @returns number of bytes sent
 */
ssize_t yamux_stream_window_update(struct YamuxChannelContext* channel_ctx, int32_t delta)
{
    if (!channel_ctx || channel_ctx->state == yamux_stream_closed
            || channel_ctx->state == yamux_stream_closing || channel_ctx->closed)
        return -EINVAL;

    struct yamux_frame f = (struct yamux_frame){
        .version  = YAMUX_VERSION,
        .type     = yamux_frame_window_update,
        .flags    = get_flags(channel_ctx),
        .streamid = channel_ctx->channel,
        .length   = (uint32_t)delta
    };

    return yamux_write_frame(channel_ctx->yamux_context->stream->stream_context, &f);
}

/***
 * Write data to the stream.
 * @param stream the stream (includes the "channel")
 * @param data_length the length of the data to be sent
 * @param data_ the data to be sent
 * @return the number of bytes sent
 */
ssize_t yamux_stream_write(struct YamuxChannelContext* channel_ctx, uint32_t data_length, void* data_)
{
	// validate parameters
	if (channel_ctx == NULL || data_ == NULL || data_length == 0)
		return -EINVAL;
	/*
    if (!((size_t)stream | (size_t)data_) || stream->state == yamux_stream_closed
            || stream->state == yamux_stream_closing || stream->session->closed)
        return -EINVAL;
	*/

    // gather details
    char* data = (char*)data_;
    char* data_end = data + data_length;
    uint32_t ws = channel_ctx->window_size;
    int id = channel_ctx->channel;

    char sendd[ws + sizeof(struct yamux_frame)];

    // Send the data, breaking it up into pieces if it is too large
    while (data < data_end) {
        uint32_t dr  = (uint32_t)(data_end - data); // length of the data for this round
        uint32_t adv = MIN(dr, ws); // the size of the data we will send this round

        struct yamux_frame f = (struct yamux_frame){
            .version  = YAMUX_VERSION   ,
            .type     = yamux_frame_data,
            .flags    = get_flags(channel_ctx),
            .streamid = id,
            .length   = adv
        };

        encode_frame(&f);
        // put the frame into the buffer
        memcpy(sendd, &f, sizeof(struct yamux_frame));
        // put the data into the buffer
        memcpy(sendd + sizeof(struct yamux_frame), data, (size_t)adv);

        // send the buffer through the network
        struct StreamMessage outgoing;
        outgoing.data = (uint8_t*)sendd;
        outgoing.data_size = adv + sizeof(struct yamux_frame);
        if (!channel_ctx->yamux_context->stream->parent_stream->write(channel_ctx->yamux_context->stream->parent_stream->stream_context, &outgoing))
        		return adv;

        // prepare to loop again
        data += adv;
    }

    return data_end - (char*)data_;
}

/***
 * Release resources of stream
 * @param stream the stream
 */
void yamux_stream_free(struct yamux_stream* stream)
{
    if (!stream)
        return;

    if (stream->free_fn)
        stream->free_fn(stream);

    struct yamux_stream s = *stream;

    for (size_t i = 0; i < s.session->cap_streams; ++i)
    {
        struct yamux_session_stream* ss = &s.session->streams[i];
        if (ss->alive && ss->stream->id == s.id)
        {
            ss->alive = 0;

            s.session->num_streams--;
            if (i == s.session->cap_streams - 1)
                s.session->cap_streams--;

            break;
        }
    }

    free(stream);
}

/***
 * process stream
 * @param stream the stream
 * @param frame the frame
 * @param incoming the stream bytes (after the frame)
 * @param incoming_size the size of incoming
 * @param session_context the SessionContext
 * @returns the number of bytes processed (can be zero) or negative number on error
 */
ssize_t yamux_stream_process(struct yamux_stream* stream, struct yamux_frame* frame, const uint8_t* incoming, size_t incoming_size, struct SessionContext* session_context)
{
    struct yamux_frame f = *frame;

    switch (f.type)
    {
        case yamux_frame_data:
            {
                if (incoming_size != (ssize_t)f.length)
                    return -1;

                if (stream->read_fn)
                    stream->read_fn(stream, f.length, (void*)incoming);

                return incoming_size;
            }
        case yamux_frame_window_update:
            {
                uint64_t nws = (uint64_t)((int64_t)stream->window_size + (int64_t)(int32_t)f.length);
                nws &= 0xFFFFFFFFLL;
                stream->window_size = (uint32_t)nws;
                break;
            }
        default:
            return -EPROTO;
    }

    return 0;
}

