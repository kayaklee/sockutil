#include "pd_ringbuffer.h"
#include "pd_log.h"

int pd_ringbuffer_init(struct PdRingBuffer *rb)
{
  int ret = 0;
  if (NULL == rb)
  {
    PD_LOG(WARN, "ringbuffer null pointer");
    ret = -1;
  }
  else if (NULL == (rb->buf = (char*)malloc(PD_RING_BUF_LEN)))
  {
    PD_LOG(WARN, "alloc ringbuffer fail, this=%p", rb);
    ret = -1;
  }
  else
  {
    rb->consumer = 0;
    rb->producer = 0;
  }
  return ret;
}

void pd_ringbuffer_destroy(struct PdRingBuffer *rb)
{
  if (NULL != rb
      && NULL != rb->buf)
  {
    free(rb->buf);
  }
}

char* pd_ringbuffer_get_producer_buffer(struct PdRingBuffer *rb)
{
  char *ret = NULL;
  if (NULL == rb)
  {
    PD_LOG(WARN, "ringbuffer null pointer");
  }
  else if (PD_RING_BUF_LEN <= (rb->producer - rb->consumer))
  {
    PD_LOG(DEBUG, "ringbuffer full, this=%p", rb);
  }
  else
  {
    int64_t normal_producer = rb->producer % PD_RING_BUF_LEN;
    ret = rb->buf + normal_producer;
  }
  return ret;
}

char* pd_ringbuffer_get_consumer_buffer(struct PdRingBuffer *rb)
{
  char *ret = NULL;
  if (NULL == rb)
  {
    PD_LOG(WARN, "ringbuffer null pointer");
  }
  else if (0 >= (rb->producer - rb->consumer))
  {
    PD_LOG(DEBUG, "ringbuffer empty, this=%p", rb);
  }
  else
  {
    int64_t normal_consumer = rb->consumer % PD_RING_BUF_LEN;
    ret = rb->buf + normal_consumer;
  }
  return ret;
}

int pd_ringbuffer_get_producer_length(struct PdRingBuffer *rb)
{
  int ret = 0;
  if (NULL == rb)
  {
    PD_LOG(WARN, "ringbuffer null pointer");
  }
  else if (PD_RING_BUF_LEN <= (rb->producer - rb->consumer))
  {
    PD_LOG(DEBUG, "ringbuffer full, this=%p", rb);
  }
  else
  {
    int64_t normal_producer = rb->producer % PD_RING_BUF_LEN;
    int64_t remainder = PD_RING_BUF_LEN - (rb->producer - rb->consumer);
    if ((normal_producer + remainder) <= PD_RING_BUF_LEN)
    {
      ret = (int)remainder;
    }
    else
    {
      ret = (int)(PD_RING_BUF_LEN - normal_producer);
    }
  }
  return ret;
}

int pd_ringbuffer_get_consumer_length(struct PdRingBuffer *rb)
{
  int ret = 0;
  if (NULL == rb)
  {
    PD_LOG(WARN, "ringbuffer null pointer");
  }
  else if (0 >= (ret = (int)(rb->producer - rb->consumer)))
  {
    PD_LOG(DEBUG, "ringbuffer empty, this=%p", rb);
  }
  else
  {
    int64_t normal_consumer = rb->consumer % PD_RING_BUF_LEN;
    int64_t remainder = rb->producer - rb->consumer;
    if ((normal_consumer + remainder) <= PD_RING_BUF_LEN)
    {
      ret = (int)remainder;
    }
    else
    {
      ret = (int)(PD_RING_BUF_LEN - normal_consumer);
    }
  }
  return ret;
}

void pd_ringbuffer_produce(struct PdRingBuffer *rb, const int length)
{
  if (NULL == rb)
  {
    PD_LOG(WARN, "ringbuffer null pointer");
  }
  else if (PD_RING_BUF_LEN < (length + rb->producer - rb->consumer))
  {
    PD_LOG(DEBUG, "ringbuffer will full, this=%p", rb);
  }
  else
  {
    rb->producer += length;
  }
}

void pd_ringbuffer_consume(struct PdRingBuffer *rb, const int length)
{
  if (NULL == rb)
  {
    PD_LOG(WARN, "ringbuffer null pointer");
  }
  else if (0 > (rb->producer - rb->consumer - length))
  {
    PD_LOG(DEBUG, "ringbuffer will empty, this=%p", rb);
  }
  else
  {
    rb->consumer += length;
  }
}

int pd_ringbuffer_get_free(struct PdRingBuffer *rb)
{
  int ret = -1;
  if (NULL == rb)
  {
    PD_LOG(WARN, "ringbuffer null pointer");
  }
  else
  {
    ret = (int)(PD_RING_BUF_LEN - (rb->producer - rb->consumer));
  }
  return ret;
}

int pd_ringbuffer_get_total(struct PdRingBuffer *rb)
{
  int ret = -1;
  if (NULL == rb)
  {
    PD_LOG(WARN, "ringbuffer null pointer");
  }
  else
  {
    ret = (int)(rb->producer - rb->consumer);
  }
  return ret;
}

