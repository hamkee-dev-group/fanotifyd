#ifndef FAN_BUF_H
#define FAN_BUF_H

#include <stddef.h>





struct buf {
	char  *data;
	size_t len;
	size_t cap;
};

void buf_init(struct buf *b);
void buf_free(struct buf *b);
void buf_reset(struct buf *b);
int  buf_reserve(struct buf *b, size_t extra);
int  buf_append(struct buf *b, const char *s, size_t n);
int  buf_appendz(struct buf *b, const char *s);
int  buf_appendc(struct buf *b, char c);
int  buf_appendf(struct buf *b, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

 
int  buf_append_json_string(struct buf *b, const char *s);
int  buf_append_json_string_n(struct buf *b, const char *s, size_t len);

#endif
