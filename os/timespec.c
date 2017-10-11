#ifdef __MACH__

#include <time.h>
#include <sys/time.h>
#include <mach/clock.h>
#include <mach/mach.h>

#include "libp2p/os/timespec.h"

int timespec_get(struct timespec *ts, int base) {
	switch (base) {
		case TIME_UTC: {
			clock_serv_t cclock;
			mach_timespec_t mts;
			host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
			clock_get_time(cclock, &mts);
			mach_port_deallocate(mach_task_self(), cclock);
			ts->tv_sec = mts.tv_sec;
			ts->tv_nsec = mts.tv_nsec;
			return base;
		}
	}
	return 0;
}
#endif
