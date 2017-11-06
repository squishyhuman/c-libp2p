#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include "config.h"
#include "frame.h"
#include "stream.h"
#include "libp2p/net/stream.h"
//#include "libp2p/yamux/yamux.h"

enum yamux_session_type
{
    yamux_session_client,
    yamux_session_server
};
enum yamux_error
{
    yamux_error_normal = 0x00,
    yamux_error_protoc = 0x01,
    yamux_error_intern = 0x02
};

struct yamux_session;
struct yamux_stream;

typedef void* (*yamux_session_get_str_ud_fn)(struct yamux_session* session, yamux_streamid newid       );
typedef void  (*yamux_session_ping_fn      )(struct yamux_session* session, uint32_t val               );
typedef void  (*yamux_session_pong_fn      )(struct yamux_session* session, uint32_t val, struct timespec dt);
typedef void  (*yamux_session_go_away_fn   )(struct yamux_session* session, enum yamux_error err       );
typedef void  (*yamux_session_new_stream_fn)(struct yamux_session* session, struct yamux_stream* stream);
typedef void  (*yamux_session_free_fn      )(struct yamux_session* sesssion                            );

struct yamux_session_stream
{
    struct yamux_stream* stream;
    int alive;
};
struct yamux_session
{
    struct yamux_config* config;

    size_t num_streams;
    size_t cap_streams;
    struct yamux_session_stream* streams;

    yamux_session_get_str_ud_fn get_str_ud_fn;
    yamux_session_ping_fn       ping_fn      ;
    yamux_session_pong_fn       pong_fn      ;
    yamux_session_go_away_fn    go_away_fn   ;
    yamux_session_new_stream_fn new_stream_fn;
    yamux_session_free_fn       free_fn      ;

    void* userdata;

    struct timespec since_ping;

    enum yamux_session_type type;

    struct Stream* parent_stream;

    yamux_streamid nextid;

    int closed;
};

/***
 * Create a new yamux session
 * @param config the configuration
 * @param sock the socket
 * @param type session type (yamux_session_server or yamux_session_client)
 * @param userdata user data
 * @returns the yamux_session struct
 */
struct yamux_session* yamux_session_new(struct yamux_config* config, struct Stream* parent_stream, enum yamux_session_type type, void* userdata);

// does not close the socket, but does close the session
void yamux_session_free(struct yamux_session* session);

// does not free used memory
ssize_t yamux_session_close(struct yamux_session* session, enum yamux_error err);

inline ssize_t yamux_session_go_away(struct yamux_session* session, enum yamux_error err)
{
    return yamux_session_close(session, err);
}

ssize_t yamux_session_ping(struct yamux_session* session, uint32_t value, int pong);

// defers to stream read handlers
ssize_t yamux_session_read(struct yamux_session* session);

struct YamuxChannelContext;
/**
 * Decode an incoming message
 * @param channel the channel
 * @param incoming the incoming bytes
 * @param incoming_size the size of the incoming bytes
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_decode(struct YamuxChannelContext* channel, const uint8_t* incoming, size_t incoming_size);
