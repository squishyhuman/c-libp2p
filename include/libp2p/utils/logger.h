#pragma once

#define LOGLEVEL_NONE 0
#define LOGLEVEL_CRITICAL 1
#define LOGLEVEL_ERROR 2
#define LOGLEVEL_INFO 3
#define LOGLEVEL_DEBUG 4
#define LOGLEVEL_VERBOSE 5

#define CURRENT_LOGLEVEL LOGLEVEL_DEBUG

/**
 * Log a message to the console
 * @param area the class it is coming from
 * @param log_level logger level
 * @param format the logging string
 * @param ... params
 */
void libp2p_logger_log(const char* area, int log_level, const char* format, ...);

/**
 * Log a debug message to the console
 * @param area the class it is coming from
 * @param format the logging string
 * @param ... params
 */
void libp2p_logger_debug(const char* area, const char* format, ...);

/**
 * Log an error message to the console
 * @param area the class it is coming from
 * @param format the logging string
 * @param ... params
 */
void libp2p_logger_error(const char* area, const char* format, ...);

