#ifndef PD_RINGBUFFER_H_
#define PD_RINGBUFFER_H_

#include <stdint.h>
#include "pd_define.h"

PD_CPP_START

struct PdRingBuffer
{
  char *buf;
  int64_t consumer;
  int64_t producer;
};

extern int pd_ringbuffer_init(struct PdRingBuffer *rb);

extern void pd_ringbuffer_destroy(struct PdRingBuffer *rb);

extern char* pd_ringbuffer_get_producer_buffer(struct PdRingBuffer *rb);

extern char* pd_ringbuffer_get_consumer_buffer(struct PdRingBuffer *rb);

extern int pd_ringbuffer_get_producer_length(struct PdRingBuffer *rb);

extern int pd_ringbuffer_get_consumer_length(struct PdRingBuffer *rb);

extern void pd_ringbuffer_produce(struct PdRingBuffer *rb, const int length);

extern void pd_ringbuffer_consume(struct PdRingBuffer *rb, const int length);

extern int pd_ringbuffer_get_free(struct PdRingBuffer *rb);

extern int pd_ringbuffer_get_total(struct PdRingBuffer *rb);

PD_CPP_END

#endif

