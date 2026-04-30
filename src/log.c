#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static enum log_level g_level = LOG_LEVEL_INFO;
static int g_stderr = 1;

void log_set_level(enum log_level lvl) { g_level = lvl; }
void log_set_use_stderr(int yes)       { g_stderr = !!yes; }
enum log_level log_get_level(void)     { return g_level; }

static const char *lvl_str(enum log_level lvl)
{
	switch (lvl) {
	case LOG_LEVEL_ERROR: return "ERROR";
	case LOG_LEVEL_WARN:  return "WARN";
	case LOG_LEVEL_INFO:  return "INFO";
	case LOG_LEVEL_DEBUG: return "DEBUG";
	}
	return "?";
}

void log_msg(enum log_level lvl, const char *fmt, ...)
{
	if ((int)lvl > (int)g_level)
		return;

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tm;
	gmtime_r(&ts.tv_sec, &tm);
	char tbuf[40];
	strftime(tbuf, sizeof tbuf, "%Y-%m-%dT%H:%M:%S", &tm);

	FILE *f = g_stderr ? stderr : stdout;
	fprintf(f, "%s.%03ldZ %-5s ", tbuf, ts.tv_nsec / 1000000, lvl_str(lvl));

	va_list ap;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	fflush(f);
}
