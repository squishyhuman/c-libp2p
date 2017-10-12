#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct yamux_config
{
    size_t   accept_backlog        ;
    uint32_t max_stream_window_size;
};

#define YAMUX_DEFAULT_WINDOW (0x100*0x400)

#define YAMUX_DEFAULT_CONFIG ((struct yamux_config)\
{\
    .accept_backlog=0x100,\
    .max_stream_window_size=YAMUX_DEFAULT_WINDOW\
})
