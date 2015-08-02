#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "pd_transport.h"
#include "pd_event.h"
#include "pd_log.h"
#include "pd_ioc.h"
#include "pd_tcp.h"

struct PdTransport
{
  struct PdSocketEvent *ev;
  pthread_t pd;
  volatile int stop_flag;
  pd_on_interval_pt on_interval_func;
  void *on_interval_arg;
  pd_handle_packet_pt handle_packet_func;
  void *handle_packet_arg;
  int64_t bind_core_id;
};

static struct PdTransport *alloc_()
{
  struct PdTransport *ret = (struct PdTransport*)malloc(sizeof(struct PdTransport));
  if (NULL != ret)
  {
    memset(ret, 0, sizeof(struct PdTransport));
  }
  return ret;
}

static void free_(struct PdTransport *ts)
{
  if (NULL != ts)
  {
    free(ts);
  }
}

static void block_process_(struct PdTransport *ts)
{
  static __thread struct PdIOEvent events[PD_MAX_SOCKET_EVENTS];
  int ret = pd_event_get_events(ts->ev, PD_TRANSPORT_LOOP_INTERVAL, events, PD_MAX_SOCKET_EVENTS);
  int i = 0;
  for (; i < ret; i++)
  {
    if (events[i].error)
    {
      if (NULL != events[i].ioc->on_error)
      {
        events[i].ioc->on_error(events[i].ioc);
        PD_LOG(DEBUG, "on error done, ioc=%p", events[i].ioc);
      }
    }
    else
    {
      int callback_ret = 0;
      if (events[i].readable
          && NULL != events[i].ioc->on_readable)
      {
        callback_ret = events[i].ioc->on_readable(events[i].ioc);
        PD_LOG(DEBUG, "on readable done, ioc=%p", events[i].ioc);
      }
      if (0 == callback_ret
          && events[i].writeable
          && NULL != events[i].ioc->on_writeable)
      {
        events[i].ioc->on_writeable(events[i].ioc);
        PD_LOG(DEBUG, "on writeable done, ioc=%p", events[i].ioc);
      }
    }
  }
}

static void *thread_loop_(void *data)
{
  struct PdTransport *ts = (struct PdTransport*)data;
  pd_bind_core(ts->bind_core_id);
  while (!ts->stop_flag)
  {
    if (NULL != ts->on_interval_func)
    {
      ts->on_interval_func(ts->on_interval_arg);
    }
    block_process_(ts);
  }
  return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

struct PdTransport *pd_transport_init(const int64_t bind_core_id)
{
  struct PdTransport *ret = alloc_();
  if (NULL == ret)
  {
    PD_LOG(WARN, "alloc transport fail");
  }
  else if (NULL == (ret->ev = pd_event_init()))
  {
    PD_LOG(WARN, "init PdSocketEvent fail, ts=%p", ret);
    free_(ret);
    ret = NULL;
  }
  else
  {
    ret->pd = 0;
    ret->stop_flag = 0;
    ret->on_interval_func = NULL;
    ret->on_interval_arg = NULL;
    ret->bind_core_id = bind_core_id;
    PD_LOG(INFO, "transport init succ, ts=%p ev=%p", ret, ret->ev);
  }
  return ret;
}

void pd_transport_destroy(struct PdTransport *ts)
{
  if (NULL == ts)
  {
    PD_LOG(WARN, "transport null pointer");
  }
  else
  {
    pd_transport_stop(ts);
    pd_transport_wait(ts);
    ts->on_interval_arg = NULL;
    ts->on_interval_func = NULL;
    ts->stop_flag = 0;
    ts->pd = 0;
    if (NULL != ts->ev)
    {
      pd_event_destroy(ts->ev);
      ts->ev = NULL;
    }
    free_(ts);
  }
}

void pd_transport_set_timer(struct PdTransport *ts, pd_on_interval_pt on_interval, void *arg)
{
  if (NULL == ts)
  {
    PD_LOG(WARN, "transport null pointer");
  }
  else
  {
    ts->on_interval_func = on_interval;
    ts->on_interval_arg = arg;
  }
}

void pd_transport_set_handler(struct PdTransport *ts, pd_handle_packet_pt handle_packet, void *arg)
{
  if (NULL == ts)
  {
    PD_LOG(WARN, "transport null pointer");
  }
  else
  {
    ts->handle_packet_func = handle_packet;
    ts->handle_packet_arg = arg;
  }
}

void pd_transport_block_process(struct PdTransport *ts)
{
  block_process_(ts);
}

int pd_transport_run(struct PdTransport *ts)
{
  int ret = 0;
  int tmp_ret = 0;
  if (NULL == ts)
  {
    PD_LOG(WARN, "transport null pointer");
    ret = -1;
  }
  else
  {
    ts->stop_flag = 0;
    if (0 != (tmp_ret = pthread_create(&ts->pd, NULL, thread_loop_, (void*)ts)))
    {
      PD_LOG(WARN, "pthread_create fail, ts=%p errno=%d", ts, tmp_ret);
      ret = -1;
    }
    else
    {
      PD_LOG(INFO, "pthread_create succ, ts=%p pd=%lu", ts, ts->pd);
    }
  }
  return ret;
}

int pd_transport_stop(struct PdTransport *ts)
{
  int ret = 0;
  if (NULL == ts)
  {
    PD_LOG(WARN, "transport null pointer");
    ret = -1;
  }
  else
  {
    ts->stop_flag = 1;
  }
  return ret;
}

int pd_transport_wait(struct PdTransport *ts)
{
  int ret = 0;
  if (NULL == ts)
  {
    PD_LOG(WARN, "transport null pointer");
    ret = -1;
  }
  else
  {
    if (0 != ts->pd)
    {
      pthread_join(ts->pd, NULL);
      ts->pd = 0;
    }
  }
  return ret;
}

int pd_transport_set_ioc(struct PdTransport *ts, struct PdIOComponent *ioc, int enable_read, int enable_write)
{
  int ret = 0;
  if (NULL == ts)
  {
    PD_LOG(WARN, "transport null pointer");
    ret = -1;
  }
  else if (NULL == ioc)
  {
    PD_LOG(WARN, "invalid param, ioc=%p", ioc);
    ret = -1;
  }
  else if (0 != (ret = pd_event_set_event(ts->ev, ioc, enable_read, enable_write)))
  {
    PD_LOG(WARN, "set ioc fail, ts=%p ev=%p ioc=%p enable_read=%d enable_write=%d",
        ts, ts->ev, ioc, enable_read, enable_write);
  }
  else
  {
    PD_LOG(DEBUG, "set ioc succ, ts=%p ev=%p ioc=%p enable_read=%d enable_write=%d",
        ts, ts->ev, ioc, enable_read, enable_write);
  }
  return ret;
}

int pd_transport_remove_ioc(struct PdTransport *ts, struct PdIOComponent *ioc)
{
  int ret = 0;
  if (NULL == ts)
  {
    PD_LOG(WARN, "transport null pointer");
    ret = -1;
  }
  else if (NULL == ioc)
  {
    PD_LOG(WARN, "invalid param, ioc=%p", ioc);
    ret = -1;
  }
  else if (0 != (ret = pd_event_remove_event(ts->ev, ioc)))
  {
    PD_LOG(WARN, "remove ioc fail, ts=%p ev=%p ioc=%p",
        ts, ts->ev, ioc);
  }
  else
  {
    PD_LOG(DEBUG, "remove ioc succ, ts=%p ev=%p ioc=%p",
        ts, ts->ev, ioc);
  }
  return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

int pd_transport_handle_packet(struct PdTransport *ts, struct PdTcpIOComponent *tcp_ioc, const char *buffer, const int length)
{
  int ret = 0;
  if (NULL == ts)
  {
    PD_LOG(WARN, "transport null pointer");
    ret = -1;
  }
  else if (NULL == ts->handle_packet_func)
  {
    PD_LOG(WARN, "handle_packet_func null pointer, this=%p", ts);
    ret = -1;
  }
  else
  {
    ret = ts->handle_packet_func(tcp_ioc, ts->handle_packet_arg, buffer, length);
  }
  return ret;
}

