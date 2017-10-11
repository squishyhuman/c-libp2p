#include <arpa/inet.h>
#include <sys/socket.h>

#include "libp2p/yamux/frame.h"

enum eness
{
    unk,
    little,
    big
};

static enum eness eness = unk;

static void set_eness()
{
    uint16_t x = 1;

    if (*(char*)&x == 1)
        eness = little;
    else
        eness = big;
}

void encode_frame(struct yamux_frame* frame)
{
    if (eness == unk)
        set_eness();

    frame->flags    = htons(frame->flags   );
    frame->streamid = htonl(frame->streamid);
    frame->length   = htonl(frame->length  );
}
void decode_frame(struct yamux_frame* frame)
{
    if (eness == unk)
        set_eness();

    frame->flags    = ntohs(frame->flags   );
    frame->streamid = ntohl(frame->streamid);
    frame->length   = ntohl(frame->length  );
}
