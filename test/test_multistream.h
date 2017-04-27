#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "libp2p/net/multistream.h"

int test_multistream_connect() {
	int retVal = 0;
	char* response;
	size_t response_size;

	struct Stream* stream = libp2p_net_multistream_connect("www.jmjatlanta.com", 4001);
	if (stream == NULL)
		goto exit;

	retVal = 1;

	exit:
	if (stream != NULL) {
		struct SessionContext ctx;
		ctx.insecure_stream = stream;
		stream->close(&ctx);
		libp2p_net_multistream_stream_free(stream);
	}

	return retVal;
}

int test_multistream_get_list() {
	int retVal = 0;
	unsigned char* response;
	size_t response_size;
	char* filtered = NULL;

	struct SessionContext session;
	session.insecure_stream = libp2p_net_multistream_connect("104.131.131.82", 4001);

	if (*((int*)session.insecure_stream->socket_descriptor) < 0)
		goto exit;

	// try to respond something, ls command
	const unsigned char* out = "ls\n";

	if (libp2p_net_multistream_write(&session, out, strlen((char*)out)) <= 0)
		goto exit;

	// retrieve response
	retVal = libp2p_net_multistream_read(&session, &response, &response_size, 5);
	if (retVal <= 0)
		goto exit;

	filtered = malloc(response_size + 1);
	strncpy(filtered, response, response_size);
	filtered[response_size] = 0;

	fprintf(stdout, "Response from multistream ls: %s", (char*)filtered);

	retVal = 1;

	exit:
	if (session.insecure_stream != NULL) {
		session.insecure_stream->close(&session);
		libp2p_net_multistream_stream_free(session.insecure_stream);
	}
	if (response != NULL)
		free(response);
	if (filtered != NULL)
		free(filtered);

	return retVal > 0;
}
