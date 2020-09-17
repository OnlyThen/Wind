#ifndef BUFFER_H
#define BUFFER_H

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

struct buffer {
	size_t max;
	size_t used;
	uint8_t *data;
};

struct buffer *buf_create(size_t init_size);
void buf_release(struct buffer *buf);
int buf_grow(struct buffer *buf);
int buf_resize(struct buffer *buf, size_t new_size);

#endif