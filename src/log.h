#ifndef FAN_LOG_H
#define FAN_LOG_H

#include <stdarg.h>

enum log_level {
	LOG_LEVEL_ERROR = 0,
	LOG_LEVEL_WARN  = 1,
	LOG_LEVEL_INFO  = 2,
	LOG_LEVEL_DEBUG = 3,
};

void log_set_level(enum log_level lvl);
void log_set_use_stderr(int yes);
enum log_level log_get_level(void);

void log_msg(enum log_level lvl, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#define log_err(...)   log_msg(LOG_LEVEL_ERROR, __VA_ARGS__)
#define log_warn(...)  log_msg(LOG_LEVEL_WARN,  __VA_ARGS__)
#define log_info(...)  log_msg(LOG_LEVEL_INFO,  __VA_ARGS__)
#define log_debug(...) log_msg(LOG_LEVEL_DEBUG, __VA_ARGS__)

#endif
