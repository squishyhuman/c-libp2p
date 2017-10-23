#include <string.h>
#include <unistd.h>
#include "varint.h"
#include "libp2p/yamux/session.h"
#include "libp2p/net/protocol.h"
#include "libp2p/net/stream.h"
#include "libp2p/conn/session.h"
#include "libp2p/utils/logger.h"

/**
 * Determines if this protocol can handle the incoming message
 * @param incoming the incoming data
 * @param incoming_size the size of the incoming data buffer
 * @returns true(1) if it can handle this message, false(0) if not
 */
int yamux_can_handle(const uint8_t* incoming, size_t incoming_size) {
	char *protocol = "/yamux/1.0.0\n";
	int protocol_size = strlen(protocol);
	// is there a varint in front?
	size_t num_bytes = 0;
	if (incoming[0] != protocol[0] && incoming[1] != protocol[1]) {
		varint_decode(incoming, incoming_size, &num_bytes);
	}
	if (incoming_size >= protocol_size - num_bytes) {
		if (strncmp(protocol, (char*) &incoming[num_bytes], protocol_size) == 0)
			return 1;
	}
	return 0;
}

/**
 * the yamux stream received some bytes. Process them
 * @param stream the stream that the data came in on
 * @param incoming_size the size of the stream buffer
 * @param incoming the stream buffer
 */
void yamux_read_stream(struct yamux_stream* stream, ssize_t incoming_size, uint8_t* incoming) {
	struct Libp2pVector* handlers = stream->userdata;
	int retVal = libp2p_protocol_marshal(incoming, incoming_size, stream->session->session_context, handlers);
	if (retVal == -1) {
		// TODO handle error condition
		libp2p_logger_error("yamux", "Marshalling returned error.\n");
	} else if (retVal > 0) {
		// TODO handle everything went okay
		libp2p_logger_debug("yamux", "Marshalling was successful. We should continue processing.\n");
	} else {
		// TODO we've been told we shouldn't do anything anymore
		libp2p_logger_debug("yamux", "Marshalling was successful. We should stop processing.\n");
	}
	return;
}

/***
 * Send the yamux protocol out the default stream
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_send_protocol(struct SessionContext* context) {
	char* protocol = "/yamux/1.0.0\n";
	if (!context->default_stream->write(context, (uint8_t*)protocol, strlen(protocol)))
		return 0;
	return 1;
}

/***
 * Check to see if the reply is the yamux protocol header we expect
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_receive_protocol(struct SessionContext* context) {
	char* protocol = "/yamux/1.0.0\n";
	struct StreamMessage* results = NULL;
	int retVal = 0;

	if (!context->default_stream->read(context, &results, 30)) {
		libp2p_logger_error("yamux", "receive_protocol: Unable to read results.\n");
		goto exit;
	}
	// the first byte is the size, so skip it
	char* ptr = strstr((char*)&results->data[1], protocol);
	if (ptr == NULL || ptr - (char*)results->data > 1) {
		goto exit;
	}
	retVal = 1;
	exit:
	libp2p_stream_message_free(results);
	return retVal;
}

/***
 * Handles the message
 * @param incoming the incoming data buffer
 * @param incoming_size the size of the incoming data buffer
 * @param session_context the information about the incoming connection
 * @param protocol_context the protocol-dependent context
 * @returns 0 if the caller should not continue looping, <0 on error, >0 on success
 */
int yamux_handle_message(const uint8_t* incoming, size_t incoming_size, struct SessionContext* session_context, void* protocol_context) {
	// they've asked to swicth to yamux. Do the switch and return 0 so that nothing else listens on this stream
	struct yamux_session* yamux = yamux_session_new(NULL, session_context, yamux_session_server, protocol_context);
	uint8_t* buf = (uint8_t*) malloc(incoming_size);
	if (buf == NULL)
		return -1;
	memcpy(buf, incoming, incoming_size);
	for(;;) {
		int retVal = yamux_decode(yamux, incoming, incoming_size);
		free(buf);
		buf = NULL;
		if (!retVal)
			break;
		else { // try to read more from this stream
			// TODO need more information as to what this loop should do
		}
	}

	/*
	struct Libp2pVector* handlers = (struct Libp2pVector*)protocol_context;
	uint8_t* results = NULL;
	size_t bytes_read = 0;
	int numRetries = 0;
	int retVal = 0;
	int max_retries = 100; // try for 5 minutes
	for(;;) {
   		// try to read for 5 seconds
   	    if (session_context->default_stream->read(session_context, &results, &bytes_read, 5)) {
   	    	// we read something from the network. Process it.
   	    	// NOTE: If it is a multistream protocol that we are receiving, ignore it.
   	    	if (yamux_can_handle(results, bytes_read))
   	    		continue;
   	    	numRetries = 0;
   	   	retVal = libp2p_protocol_marshal(results, bytes_read, session_context, handlers);
   	   	if (results != NULL)
   	   		free(results);
   	   	// exit the loop on error (or if they ask us to no longer loop by returning 0)
   	   	if (retVal <= 0)
   	   		break;
   	    } else {
   	    		// we were unable to read from the network.
   	   	    // if it timed out, we should try again (if we're not out of retries)
   	    		if (numRetries >= max_retries)
   	    			break;
   	    		numRetries++;
   	    }
	}
	*/
	return 0;
}

/**
 * Shutting down. Clean up any memory allocations
 * @param protocol_context the context
 * @returns true(1)
 */
int yamux_shutdown(void* protocol_context) {
	return 0;
}

struct Libp2pProtocolHandler* yamux_build_protocol_handler(struct Libp2pVector* handlers) {
	struct Libp2pProtocolHandler* handler = libp2p_protocol_handler_new();
	if (handler != NULL) {
		handler->context = handlers;
		handler->CanHandle = yamux_can_handle;
		handler->HandleMessage = yamux_handle_message;
		handler->Shutdown = yamux_shutdown;
	}
	return handler;
}
