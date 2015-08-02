#include <stdlib.h>
#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include "pd_event.h"
#include "pd_log.h"
#include "pd_ioc.h"
#include "pd_socket.h"

struct PdSocketEvent
{
  int epoll_fd;
};

static struct PdSocketEvent *alloc_();

static void free_(struct PdSocketEvent *ev);

////////////////////////////////////////////////////////////////////////////////////////////////////

struct PdSocketEvent *alloc_()
{
  struct PdSocketEvent *ret = (struct PdSocketEvent*)malloc(sizeof(struct PdSocketEvent));
  if (NULL != ret)
  {
    ret->epoll_fd = -1;
  }
  return ret;
}

void free_(struct PdSocketEvent *ev)
{
  if (NULL != ev)
  {
    free(ev);
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

struct PdSocketEvent *pd_event_init()
{
  struct PdSocketEvent *ret = NULL;
  if (NULL == (ret = alloc_()))
  {
    PD_LOG(WARN, "alloc PdSocketEvent fail");
  }
  else if (-1 == (ret->epoll_fd = epoll_create(PD_MAX_SOCKET_EVENTS)))
  {
    PD_LOG(WARN, "epoll_create fail, errno=%u", errno);
    free(ret);
    ret = NULL;
  }
  else
  {
    PD_LOG(INFO, "epoll_create succ, epoll_fd=%d", ret->epoll_fd);
  }
  return ret;
}

void pd_event_destroy(struct PdSocketEvent *ev)
{
  if (NULL == ev)
  {
    PD_LOG(WARN, "ev null pointer");
  }
  else
  {
    if (-1 != ev->epoll_fd)
    {
      close(ev->epoll_fd);
      ev->epoll_fd = -1;
    }
    free_(ev);
  }
}

int pd_event_set_event(struct PdSocketEvent *ev, struct PdIOComponent *ioc, int enable_read, int enable_write)
{
  int ret = 0;
  if (NULL == ev || NULL == ioc || NULL == ioc->sock)
  {
    PD_LOG(WARN, "invalid param, ev=%p ioc=%p sock=%p", ev, ioc, ioc->sock);
    ret = -1;
  }
  else if ((ioc->in_epoll_read == enable_read)
      && (ioc->in_epoll_write == enable_write))
  {
    // need not
  }
  else
  {
    struct epoll_event epoll_ev;
    memset(&epoll_ev, 0, sizeof(epoll_ev));
    epoll_ev.data.ptr = ioc;
    epoll_ev.events = 0;
    if (enable_write)
    {
      epoll_ev.events |= EPOLLOUT;
    }
    if (enable_read)
    {
      epoll_ev.events |= EPOLLIN;
    }
    int op = (ioc->in_epoll_read || ioc->in_epoll_write) ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    if (0 != epoll_ctl(ev->epoll_fd, op, pd_socket_get_fd(ioc->sock), &epoll_ev))
    {
      PD_LOG(WARN, "epoll_ctl fail, op=%d errno=%u epoll_fd=%d sock_fd=%d ioc=%p",
          errno, op, ev->epoll_fd, pd_socket_get_fd(ioc->sock), ioc);
      ret = -1;
    }
    else
    {
      ioc->in_epoll_read = enable_read;
      ioc->in_epoll_write = enable_write;
      PD_LOG(DEBUG, "epoll_ctl mod succ, epoll_fd=%d sock_fd=%d ioc=%p",
          ev->epoll_fd, pd_socket_get_fd(ioc->sock), ioc);
    }
  }
  return ret;
}

int pd_event_remove_event(struct PdSocketEvent *ev, struct PdIOComponent *ioc)
{
  int ret = 0;
  if (NULL == ev || NULL == ioc || NULL == ioc->sock)
  {
    PD_LOG(WARN, "invalid param, ev=%p ioc=%p sock=%p", ev, ioc, ioc->sock);
    ret = -1;
  }
  else
  {
    struct epoll_event epoll_ev;
    memset(&epoll_ev, 0, sizeof(epoll_ev));
    epoll_ev.data.ptr = ioc;
    epoll_ev.events = 0;
    if (0 != epoll_ctl(ev->epoll_fd, EPOLL_CTL_DEL, pd_socket_get_fd(ioc->sock), &epoll_ev))
    {
      PD_LOG(WARN, "epoll_ctl del fail, errno=%u epoll_fd=%d sock_fd=%d ioc=%p",
          errno, ev->epoll_fd, pd_socket_get_fd(ioc->sock), ioc);
      ret = -1;
    }
    else
    {
      ioc->in_epoll_read = 0;
      ioc->in_epoll_write = 0;
      PD_LOG(DEBUG, "epoll_ctl del succ, epoll_fd=%d sock_fd=%d ioc=%p",
          ev->epoll_fd, pd_socket_get_fd(ioc->sock), ioc);
    }
  }
  return ret;
}

int pd_event_get_events(struct PdSocketEvent *ev, int timeout_us, struct PdIOEvent *events, int events_cnt)
{
  int ret = 0;
  if (NULL == ev || NULL == events || 0 >= events_cnt)
  {
    PD_LOG(WARN, "invalid param, ev=%p events=%p events_cnt=%d", ev, events, events_cnt);
    ret = -1;
  }
  else
  {
    struct epoll_event epoll_events[PD_MAX_SOCKET_EVENTS];
    if (events_cnt > PD_MAX_SOCKET_EVENTS)
    {
      events_cnt = PD_MAX_SOCKET_EVENTS;
    }

    ret = epoll_wait(ev->epoll_fd, epoll_events, events_cnt, timeout_us / 1000);

    if (0 < ret)
    {
      memset(events, 0, sizeof(struct PdIOEvent) * (uint32_t)ret);
    }

    int i = 0;
    for (; i < ret; i++)
    {
      events[i].ioc = epoll_events[i].data.ptr;
      if (epoll_events[i].events & (EPOLLERR | EPOLLHUP))
      {
        events[i].error = 1;
      }
      if ((epoll_events[i].events & EPOLLIN) != 0)
      {
        events[i].readable = 1;
      }
      if ((epoll_events[i].events & EPOLLOUT) != 0)
      {
        events[i].writeable = 1;
      }
    }
  }
  return ret;
}

