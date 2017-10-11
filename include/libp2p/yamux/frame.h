#pragma once

#include <stdint.h>
#include <stddef.h>

typedef uint8_t  yamux_version ;
typedef uint32_t yamux_streamid;

#define YAMUX_VERSION (0x00)
#define YAMUX_STREAMID_SESSION (0)

enum yamux_frame_type
{
    yamux_frame_data          = 0x00,
    yamux_frame_window_update = 0x01,
    yamux_frame_ping          = 0x02,
    yamux_frame_go_away       = 0x03
};
enum yamux_frame_flags
{
    yamux_frame_nil = 0x0000,

    yamux_frame_syn = 0x0001,
    yamux_frame_ack = 0x0002,
    yamux_frame_fin = 0x0004,
    yamux_frame_rst = 0x0008
};

#pragma pack(push,1)
struct yamux_frame
{
    yamux_version  version ;
    uint8_t        type    ;
    uint16_t       flags   ;
    yamux_streamid streamid;
    uint32_t       length  ;
};
#pragma pack(pop)

void encode_frame(struct yamux_frame* frame);
void decode_frame(struct yamux_frame* frame);


