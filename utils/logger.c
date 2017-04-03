#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "libp2p/utils/logger.h"

char* logger_classes[] = { "secio", "null" };
int logger_classes_len = 2;

/**
 * Log a message to the console
 * @param area the class it is coming from
 * @param log_level logger level
 * @param format the logging string
 * @param ... params
 */
void libp2p_logger_log(const char* area, int log_level, const char* format, ...) {
	if (log_level <= CURRENT_LOGLEVEL) {
		int found = 0;
		for (int i = 0; i < logger_classes_len; i++) {
			if (strcmp(logger_classes[i], area) == 0) {
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
	if (log_level <= CURRENT_LOGLEVEL) {
		int found = 0;
		for (int i = 0; i < logger_classes_len; i++) {
			if (strcmp(logger_classes[i], area) == 0) {
				found = 1;
				break;
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
