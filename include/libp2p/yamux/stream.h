#pragma once

#include <stddef.h>
#include <stdint.h>

#include "session.h"
#include "libp2p/conn/session.h"
#include "libp2p/yamux/yamux.h"

// forward declarations
struct YamuxChannelContext;

// NOTE: 'data' is not guaranteed to be preserved when the read_fn
// handler exists (read: it will be freed).
struct yamux_stream;

typedef void (*yamux_stream_read_fn)(struct yamux_stream* stream, uint32_t data_length, void* data);
typedef void (*yamux_stream_fin_fn )(struct yamux_stream* stream);
typedef void (*yamux_stream_rst_fn )(struct yamux_stream* stream);
typedef void (*yamux_stream_free_fn)(struct yamux_stream* stream);

enum yamux_stream_state
{
    yamux_stream_inited,
    yamux_stream_syn_sent,
    yamux_stream_syn_recv,
    yamux_stream_est,
    yamux_stream_closing,
    yamux_stream_closed
};

struct yamux_stream
{
    struct yamux_session* session;

    yamux_stream_read_fn read_fn;
    yamux_stream_fin_fn  fin_fn ;
    yamux_stream_rst_fn  rst_fn ;
    yamux_stream_free_fn free_fn;

    struct Stream* stream;

    enum yamux_stream_state state;

    yamux_streamid id;

    uint32_t window_size;
};

/**
 * Create a new stream that has a YamuxChannelContext
 * @param context the Yamux context
 * @param id the stream id
 * @param msg the incoming message
 * @returns a stream that is a Yamux channel
 */
struct Stream* yamux_channel_new(struct YamuxContext* context, yamux_streamid id, struct StreamMessage* msg);

// not obligatory, SYN is sent by yamux_stream_write when the stream
// isn't initialised anyway
ssize_t yamux_stream_init (struct YamuxChannelContext* channel_ctx);

/***
 * Closes the stream
 * NOTE: doesn't free the stream, uses FIN
 * @param context the YamuxContext or YamuxChannelContext
 * @returns number of bytes sent
 */
ssize_t yamux_stream_close(void* context);
// uses RST
ssize_t yamux_stream_reset(struct YamuxChannelContext* stream);

void yamux_stream_free(struct yamux_stream* stream);

ssize_t yamux_stream_window_update(struct YamuxChannelContext* ctx, int32_t delta);
ssize_t yamux_stream_write(struct YamuxChannelContext* ctx, uint32_t data_length, void* data);

/***
 * process stream
 * @param stream the stream
 * @param frame the frame
 * @param incoming the stream bytes (after the frame)
 * @param incoming_size the size of incoming
 * @returns the number of bytes processed (can be zero) or negative number on error
 */
ssize_t yamux_stream_process(struct yamux_stream* stream, struct yamux_frame* frame, const uint8_t* incoming, size_t incoming_size);

/**
 * Retrieve the flags for this context
 * @param context the context
 * @returns the correct flag
 */
enum yamux_frame_flags get_flags(void* context);

