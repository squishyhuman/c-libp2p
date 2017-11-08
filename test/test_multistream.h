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
		stream->close(stream);
		libp2p_net_multistream_stream_free(stream);
	}

	return retVal;
}

int test_multistream_get_list() {
	int retVal = 0;
	struct StreamMessage* response;
	char* filtered = NULL;

	struct SessionContext session;
	session.insecure_stream = libp2p_net_multistream_connect("10.211.55.2", 4001);

	if (session.insecure_stream == NULL)
		goto exit;

	// try to respond something, ls command
	struct StreamMessage outgoing;
	outgoing.data = (uint8_t*)"ls\n";
	outgoing.data_size = 3;
	if (libp2p_net_multistream_write(&session, &outgoing) <= 0)
		goto exit;

	// retrieve response
	retVal = libp2p_net_multistream_read(&session, &response, 5);
	if (retVal <= 0)
		goto exit;

	filtered = malloc(response->data_size + 1);
	strncpy(filtered, (char*)response->data, response->data_size);
	filtered[response->data_size] = 0;

	fprintf(stdout, "Response from multistream ls: %s", (char*)filtered);

	retVal = 1;

	exit:
	if (session.insecure_stream != NULL) {
		session.insecure_stream->close(session.insecure_stream);
		libp2p_net_multistream_stream_free(session.insecure_stream);
	}
	libp2p_stream_message_free(response);
	if (filtered != NULL)
		free(filtered);

	return retVal > 0;
}
