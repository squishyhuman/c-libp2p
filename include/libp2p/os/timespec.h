#pragma once

/**
 * mac doesn't have timespec_get
 */

#ifdef __MACH__
#include <time.h>
#define TIME_UTC 1
int timespec_get(struct timespec *ts, int base);
#endif
