#include "buf.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void buf_init(struct buf *b)
{
	b->data = NULL;
	b->len = 0;
	b->cap = 0;
}

void buf_free(struct buf *b)
{
	free(b->data);
	b->data = NULL;
	b->len = b->cap = 0;
}

void buf_reset(struct buf *b)
{
	b->len = 0;
	if (b->data && b->cap > 0)
		b->data[0] = '\0';
}

int buf_reserve(struct buf *b, size_t extra)
{
	size_t need = b->len + extra + 1;
	if (need <= b->cap)
		return 0;
	size_t cap = b->cap ? b->cap : 64;
	while (cap < need)
		cap *= 2;
	char *p = realloc(b->data, cap);
	if (!p)
		return -1;
	b->data = p;
	b->cap = cap;
	return 0;
}

int buf_append(struct buf *b, const char *s, size_t n)
{
	if (buf_reserve(b, n) < 0)
		return -1;
	memcpy(b->data + b->len, s, n);
	b->len += n;
	b->data[b->len] = '\0';
	return 0;
}

int buf_appendz(struct buf *b, const char *s)
{
	return buf_append(b, s, strlen(s));
}

int buf_appendc(struct buf *b, char c)
{
	if (buf_reserve(b, 1) < 0)
		return -1;
	b->data[b->len++] = c;
	b->data[b->len] = '\0';
	return 0;
}

int buf_appendf(struct buf *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	va_list ap2;
	va_copy(ap2, ap);
	int n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0) {
		va_end(ap2);
		return -1;
	}
	if (buf_reserve(b, (size_t)n) < 0) {
		va_end(ap2);
		return -1;
	}
	int m = vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap2);
	va_end(ap2);
	if (m < 0)
		return -1;
	b->len += (size_t)m;
	return 0;
}

int buf_append_json_string_n(struct buf *b, const char *s, size_t len)
{
	if (buf_appendc(b, '"') < 0)
		return -1;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '"' || c == '\\') {
			if (buf_appendc(b, '\\') < 0 || buf_appendc(b, (char)c) < 0)
				return -1;
		} else if (c == '\n') {
			if (buf_append(b, "\\n", 2) < 0)
				return -1;
		} else if (c == '\r') {
			if (buf_append(b, "\\r", 2) < 0)
				return -1;
		} else if (c == '\t') {
			if (buf_append(b, "\\t", 2) < 0)
				return -1;
		} else if (c == '\b') {
			if (buf_append(b, "\\b", 2) < 0)
				return -1;
		} else if (c == '\f') {
			if (buf_append(b, "\\f", 2) < 0)
				return -1;
		} else if (c < 0x20) {
			if (buf_appendf(b, "\\u%04x", c) < 0)
				return -1;
		} else {
			if (buf_appendc(b, (char)c) < 0)
				return -1;
		}
	}
	return buf_appendc(b, '"');
}

int buf_append_json_string(struct buf *b, const char *s)
{
	return buf_append_json_string_n(b, s, strlen(s));
}
