#include "pd_accepter.h"
#include "pd_socket.h"
#include "pd_log.h"
#include "pd_tcp.h"
#include "pd_ioc.h"
#include "pd_transport.h"

int pd_listen_on_readable(struct PdIOComponent *ioc)
{
  int ret = 0;
  struct PdSocket *accept_sock = NULL;
  struct PdIOComponent *accept_ioc = NULL;
  if (NULL == ioc)
  {
    PD_LOG(WARN, "ioc null pointer");
  }
  else if (NULL == ioc->sock)
  {
    PD_LOG(WARN, "sock null pointer");
  }
  else if (NULL == ioc->ts)
  {
    PD_LOG(WARN, "ts null pointer");
  }
  else if (NULL == (accept_sock = pd_socket_accept_tcp_client(ioc->sock)))
  {
    PD_LOG(WARN, "accept sock fail, listen_sock=%p", ioc->sock);
  }
  else if (NULL == (accept_ioc = pd_tcp_ioc_alloc()))
  {
    PD_LOG(WARN, "alloc ioc fail, accept_sock=%p", accept_sock);
    pd_socket_destroy(accept_sock);
  }
  else
  {
    accept_ioc->sock = accept_sock;
    accept_ioc->ts = ioc->ts;
    accept_ioc->on_readable = pd_tcp_on_readable;
    accept_ioc->on_writeable = pd_tcp_on_writeable;
    accept_ioc->on_error = pd_tcp_on_error;
    accept_ioc->in_epoll_read = 0;
    accept_ioc->in_epoll_write = 0;
    accept_ioc->tmp_pos = 0;
    if (0 != pd_transport_set_ioc(ioc->ts, accept_ioc, 1, 0))
    {
      PD_LOG(WARN, "pd_transport_set_ioc fail, accept_ioc=%p", accept_ioc);
      pd_socket_destroy(accept_sock);
      pd_tcp_ioc_free(accept_ioc);
    }
  }
  return ret;
}

int pd_listen_on_writeable(struct PdIOComponent *ioc)
{
  int ret = 0;
  PD_LOG(FATAL, "unexpected error, listen fd cannot be writeable, ioc=%p", ioc);
  return ret;
}

void pd_listen_on_error(struct PdIOComponent *ioc)
{
  PD_LOG(FATAL, "unexpected error, listen fd cannot be error, ioc=%p", ioc);
}

