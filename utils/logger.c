#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "libp2p/utils/logger.h"
#include "libp2p/utils/vector.h"

/**
 * A class to handle logging
 */

struct Libp2pVector* logger_classes = NULL;

/**
 * Initialize the logger. This should be done only once.
 */
void libp2p_logger_init() {
	logger_classes = libp2p_utils_vector_new(1);
}

/***
 * Checks to see if the logger has been initialized
 */
int libp2p_logger_initialized() {
	if (logger_classes == NULL)
		return 0;
	return 1;
}

int libp2p_logger_free() {
	if (logger_classes != NULL) {
		for(int i = 0; i < logger_classes->total; i++) {
			free(libp2p_utils_vector_get(logger_classes, i));
		}
		libp2p_utils_vector_free(logger_classes);
	}
	return 1;
}

/***
 * Add a class to watch for logging messages
 * @param str the class name to watch
 */
void libp2p_logger_add_class(const char* str) {
	if (!libp2p_logger_initialized())
		libp2p_logger_init();
	char* ptr = malloc(strlen(str) + 1);
	strcpy(ptr, str);
	libp2p_utils_vector_add(logger_classes, ptr);
}

/**
 * Log a message to the console
 * @param area the class it is coming from
 * @param log_level logger level
 * @param format the logging string
 * @param ... params
 */
void libp2p_logger_log(const char* area, int log_level, const char* format, ...) {
	if (!libp2p_logger_initialized())
		libp2p_logger_init();
	if (log_level <= CURRENT_LOGLEVEL) {
		int found = 0;
		for (int i = 0; i < logger_classes->total; i++) {
			if (strcmp(libp2p_utils_vector_get(logger_classes, i), area) == 0) {
				found = 1;
				break;
			}
		}
		if (found) {
			va_list argptr;
			va_start(argptr, format);
			vfprintf(stderr, format, argptr);
			va_end(argptr);
		}
	}
}

/**
 * Log a message to the console
 * @param area the class it is coming from
 * @param log_level logger level
 * @param format the logging string
 * @param ... params
 */
void libp2p_logger_vlog(const char* area, int log_level, const char* format, va_list argptr) {
	if (!libp2p_logger_initialized())
		libp2p_logger_init();
	// only allow a message if the message log level is less than the current loglevel
	if (log_level <= CURRENT_LOGLEVEL) {
		int found = 0;
		// error should always be printed for now. We need to think about this more...
		if (log_level <= LOGLEVEL_ERROR )
			found = 1;
		else {
			for (int i = 0; i < logger_classes->total; i++) {
				if (strcmp(libp2p_utils_vector_get(logger_classes, i), area) == 0) {
					found = 1;
					break;
				}
			}
		}
		if (found) {
			vfprintf(stderr, format, argptr);
		}
	}
}

/**
 * Log a debug message to the console
 * @param area the class it is coming from
 * @param format the logging string
 * @param ... params
 */
void libp2p_logger_debug(const char* area, const char* format, ...) {
	va_list argptr;
	va_start(argptr, format);
	libp2p_logger_vlog(area, LOGLEVEL_DEBUG, format, argptr);
	va_end(argptr);
}

/**
 * Log an error message to the console
 * @param area the class it is coming from
 * @param format the logging string
 * @param ... params
 */
void libp2p_logger_error(const char* area, const char* format, ...) {
	va_list argptr;
	va_start(argptr, format);
	libp2p_logger_vlog(area, LOGLEVEL_ERROR, format, argptr);
	va_end(argptr);
}

/**
 * Log an info message to the console
 * @param area the class it is coming from
 * @param format the logging string
 * @param ... params
 */
void libp2p_logger_info(const char* area, const char* format, ...) {
	va_list argptr;
	va_start(argptr, format);
	libp2p_logger_vlog(area, LOGLEVEL_INFO, format, argptr);
	va_end(argptr);
}
