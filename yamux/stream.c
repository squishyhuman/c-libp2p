
#include <errno.h>
#include <memory.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>

#include "libp2p/conn/session.h"
#include "libp2p/net/stream.h"
#include "libp2p/yamux/frame.h"
#include "libp2p/yamux/stream.h"
#include "libp2p/yamux/yamux.h"

#define MIN(x,y) (y^((x^y)&-(x<y)))
#define MAX(x,y) (x^((x^y)&-(x<y)))

// forward declarations
struct YamuxContext* libp2p_yamux_get_context(void* context);

/***
 * Create a new stream
 * @param context the yamux context
 * @param id the id (0 to set it to the next id)
 * @Param msg the message (probably the protocol id)
 * @returns a new yamux_stream struct
 */
struct Stream* yamux_channel_new(struct YamuxContext* context, yamux_streamid id, struct StreamMessage* msg)
{
    if (!context)
        return NULL;

    struct yamux_session* session = context->session;

    if (!id)
    {
        id = session->nextid;
        session->nextid += 2;
    }

    struct yamux_stream* y_stream = NULL;
    struct yamux_session_stream* session_stream = NULL;

    if (session->num_streams != session->cap_streams) {
    	// attempt to reuse dead streams
        for (size_t i = 0; i < session->cap_streams; ++i)
        {
            session_stream = &session->streams[i];

            if (!session_stream->alive)
            {
                y_stream = session_stream->stream;
                session_stream->alive = 1;
                goto FOUND;
            }
        }
    }

    if (session->cap_streams == session->config->accept_backlog)
        return NULL;

    // we didn't find a dead stream, so create a new one
    session_stream = &session->streams[session->cap_streams];

    if (session_stream->alive)
        return NULL;

    session->cap_streams++;

    session_stream->alive = 1;
    y_stream = session_stream->stream = malloc(sizeof(struct yamux_stream));

FOUND:;

    struct yamux_stream nst = (struct yamux_stream){
        .id          = id,
        .session     = session,
        .state       = yamux_stream_inited,
        .window_size = YAMUX_DEFAULT_WINDOW,

        .read_fn = NULL,
        .fin_fn  = NULL,
        .rst_fn  = NULL,
		.stream  = libp2p_yamux_channel_stream_new(context->stream, id)
    };
    *y_stream = nst;

    /*
    if (libp2p_protocol_marshal(msg, nst.stream, context->protocol_handlers) >= 0) {
    	// success
    }
    */
    struct Stream* channelStream = libp2p_yamux_channel_stream_new(context->stream, id);
    struct YamuxChannelContext* channel = (struct YamuxChannelContext*)channelStream->stream_context;
    channel->channel = id;
    channel->child_stream = NULL;
    channel->state = yamux_stream_inited;


    return channelStream;
}

/**
 * Write a raw yamux frame to the network
 * @param ctx the stream context
 * @param f the frame
 * @returns number of bytes sent, 0 on error
 */
int yamux_write_frame(void* context, struct yamux_frame* f) {
	if (context == NULL)
		return 0;
	encode_frame(f);
	struct StreamMessage outgoing;
	outgoing.data = (uint8_t*)f;
	outgoing.data_size = sizeof(struct yamux_frame);
	struct YamuxContext* ctx = libp2p_yamux_get_context(context);
	if (!ctx->stream->parent_stream->write(ctx->stream->parent_stream->stream_context, &outgoing))
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
 * @param context the YamuxChannelContext or YamuxContext
 * @returns the number of bytes sent
 */
ssize_t yamux_stream_close(void* context)
{
	if ( ((char*)context)[0] == YAMUX_CHANNEL_CONTEXT) {
		struct YamuxChannelContext* channel_ctx = (struct YamuxChannelContext*) context;
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
	} else if ( ((char*)context)[0] == YAMUX_CONTEXT) {
		struct YamuxContext* ctx = (struct YamuxContext*)context;
	    struct yamux_frame f = (struct yamux_frame){
	        .version  = YAMUX_VERSION,
	        .type     = yamux_frame_window_update,
	        .flags    = yamux_frame_fin,
	        .streamid = 0,
	        .length   = 0
	    };

	    return yamux_write_frame(ctx, &f);
	}
	return 0;
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

/**
 * Retrieve the flags for this context
 * @param context the context
 * @returns the correct flag
 */
enum yamux_frame_flags get_flags(void* context) {
	if (context == NULL)
		return 0;
	if ( ((char*)context)[0] == YAMUX_CHANNEL_CONTEXT) {
		struct YamuxChannelContext* ctx = (struct YamuxChannelContext*)context;
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
	} else if ( ((char*)context)[0] == YAMUX_CONTEXT) {
		struct YamuxContext* ctx = (struct YamuxContext*)context;
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
	return 0;
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
    uint32_t id = channel_ctx->channel;

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

struct yamux_stream* yamux_stream_new() {
	struct yamux_stream* out = (struct yamux_stream*) malloc(sizeof(struct yamux_stream));
	if (out != NULL) {
		memset(out, 0, sizeof(struct yamux_stream));
	}
	return out;
}

/***
 * process stream
 * @param stream the stream
 * @param frame the frame
 * @param incoming the stream bytes (after the frame)
 * @param incoming_size the size of incoming
 * @returns the number of bytes processed (can be zero) or negative number on error
 */
ssize_t yamux_stream_process(struct yamux_stream* stream, struct yamux_frame* frame, const uint8_t* incoming, size_t incoming_size)
{
    struct yamux_frame f = *frame;

    switch (f.type)
    {
        case yamux_frame_window_update:
            {
                uint64_t nws = (uint64_t) ( (int64_t)stream->window_size + (int64_t)(int32_t)f.length );
                nws &= 0xFFFFFFFFLL;
                stream->window_size = (uint32_t)nws;
            }
            //no break
        case yamux_frame_data:
            {
                if (incoming_size != (ssize_t)f.length)
                    return -1;

                if (stream->read_fn)
                    stream->read_fn(stream, f.length, (void*)incoming);

                return incoming_size;
            }
        default:
            return -EPROTO;
    }

    return 0;
}

