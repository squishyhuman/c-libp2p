
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#include "libp2p/yamux/session.h"
#include "libp2p/yamux/frame.h"
#include "libp2p/yamux/stream.h"

static void on_read(struct yamux_stream* stream, uint32_t data_len, void* data)
{
    char d[data_len + 1];
    d[data_len] = 0;
    memcpy(d, data, data_len);

    printf("%s", d);
}
static void on_new(struct yamux_session* session, struct yamux_stream* stream)
{
    stream->read_fn = on_read;
}

static struct sockaddr_in addr;

int init_server(int sock) {
    int err;
    //printf("bind\n");
    if ((err = bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in))) < 0)
        return err;

    //printf("listen\n");
    if ((err = listen(sock, 0x80)) < 0)
        return err;

    //printf("accept\n");
    return accept(sock, NULL, NULL);
}

int init_client(int sock) {
    int err;
    //printf("connect\n");
    if ((err = connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in))) < 0)
        return err;

    return sock;
}

int do_server() {
    int sock;
    int e = 0;
    ssize_t ee;

    // init sock
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        e = errno;
        printf("socket() failed with %i\n", e);

        goto END;
    }

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port        = htons(1337);

    int s2 = -1;
    ssize_t initr = init_server(sock);
    if (initr < 0)
    {
        e = errno;
        printf("init failed with %i, errno=%i\n", (int)-initr, e);

        goto FREE_SOCK;
    }
    s2 = (int)initr;

    // init yamux
    struct yamux_session* sess = yamux_session_new(NULL, s2,
            yamux_session_server
            , NULL);
    if (!sess)
    {
        printf("yamux_session_new() failed\n");

        goto FREE_SOCK;
    }
    sess->new_stream_fn = on_new;

    for (;;) {
        if ((ee = yamux_session_read(sess)) < 0)
        {
            e = errno;
            printf("yamux_session_read() failed with %i, errno=%i\n", (int)-ee, e);

            goto KILL_STRM;
        }

    }

KILL_STRM:
    yamux_session_free(sess);
FREE_SOCK:
    close(sock);
END:
    return 0;
}

int do_client() {
    int sock;
    int e = 0;
    ssize_t ee;

    // init sock
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        e = errno;
        printf("socket() failed with %i\n", e);

        goto END;
    }

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port        = htons(1337);

    int s2 = -1;
    ssize_t initr = init_client(sock);
    if (initr < 0)
    {
        e = errno;
        printf("init failed with %i, errno=%i\n", (int)-initr, e);

        goto FREE_SOCK;
    }
    s2 = (int)initr;

    // init yamux
    struct yamux_session* sess = yamux_session_new(NULL, s2,
            yamux_session_client
            , NULL);
    if (!sess)
    {
        printf("yamux_session_new() failed\n");

        goto FREE_SOCK;
    }
    sess->new_stream_fn = on_new;

    struct yamux_stream* strm = yamux_channel_new(sess, 0, NULL);
    if (!strm)
    {
        printf("yamux_new_stream() failed\n");

        goto FREE_YAMUX;
    }

    strm->read_fn = on_read;

    if ((ee = yamux_stream_init(strm)) < 0)
    {
        e = errno;
        printf("yamux_stream_init() failed with %i, errno=%i\n", (int)-ee, e);

        goto KILL_STRM;
    }

    char str[] = "hello\n";
    if ((ee = yamux_stream_write(strm, 6, str)) < 0)
    {
        e = errno;
        printf("yamux_stream_write() failed with %i, errno=%i\n", (int)-ee, e);

        goto KILL_STRM;
    }

    for (;;) {
        if ((ee = yamux_session_read(sess)) < 0)
        {
            e = errno;
            printf("yamux_session_read() failed with %i, errno=%i\n", (int)-ee, e);

            goto KILL_STRM;
        }

        break;
    }

KILL_STRM:
    if (yamux_stream_reset(strm))
        goto FREE_STRM;
FREE_STRM:
    yamux_stream_free(strm);

FREE_YAMUX:
    yamux_session_free(sess);
FREE_SOCK:
    close(sock);
END:
    return 0;

}

int main(int argc, char* argv[])
{
    int e = 0;
    int client = -1;

	if (argc < 2) {
		e = 1;
	} else {
		if (strcmp(argv[1], "client") == 0)
			client = 1;
		if (strcmp(argv[1], "server") == 0)
			client = 0;
	}

	if (e || client == -1) {
		fprintf(stderr, "Syntax: %s server or %s client\n", argv[0], argv[0]);
		exit(e);
	}

	if (client)
		return do_client();
	else
		return do_server();

}

