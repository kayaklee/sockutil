#include <string.h>
#include <errno.h>
#include "pd_tcp.h"
#include "pd_ringbuffer.h"
#include "pd_socket.h"
#include "pd_log.h"
#include "pd_ioc.h"
#include "pd_transport.h"

struct PdTcpIOComponent
{
  struct PdIOComponent base_ioc;
  struct PdRingBuffer recv_buf;
  struct PdRingBuffer post_buf;
};

static int pd_tcp_read_stream(struct PdTcpIOComponent *tcp_ioc)
{
  int ret = 0;
  while (1)
  {
    char *buffer = pd_ringbuffer_get_producer_buffer(&tcp_ioc->recv_buf);
    int length = pd_ringbuffer_get_producer_length(&tcp_ioc->recv_buf);
    if (NULL == buffer
        || 0 >= length)
    {
      break;
    }
    int readlen = read(pd_socket_get_fd(tcp_ioc->base_ioc.sock), buffer, length);
    if (-1 == readlen)
    {
      if (EINTR == errno)
      {
        continue;
      }
      else
      {
        break;
      }
    }
    if (0 < readlen)
    {
      pd_ringbuffer_produce(&tcp_ioc->recv_buf, readlen);
      PD_LOG(DEBUG, "read from peer=[%s], readlen=%d producer_length=%d",
          pd_socket_str_peer(tcp_ioc->base_ioc.sock),
          readlen,
          pd_ringbuffer_get_producer_length(&tcp_ioc->recv_buf));
    }
    if (0 == readlen)
    {
      PD_LOG(DEBUG, "peer close tcp, peer=[%s]", pd_socket_str_peer(tcp_ioc->base_ioc.sock));
      pd_tcp_on_error((struct PdIOComponent*)tcp_ioc);
      ret = PD_ERR_IOC_DESTROY;
      break;
    }
  }
  return ret;
}

static int pd_tcp_write_stream(struct PdTcpIOComponent *tcp_ioc)
{
  int ret = 0;
  while (1)
  {
    char *buffer = pd_ringbuffer_get_consumer_buffer(&tcp_ioc->post_buf);
    int length = pd_ringbuffer_get_consumer_length(&tcp_ioc->post_buf);
    if (NULL == buffer
        || 0 >= length)
    {
      pd_transport_set_ioc(tcp_ioc->base_ioc.ts, (struct PdIOComponent*)tcp_ioc, 1, 0);
      break;
    }
    int writelen = write(pd_socket_get_fd(tcp_ioc->base_ioc.sock), buffer, length);
    if (-1 == writelen)
    {
      if (EINTR == errno)
      {
        continue;
      }
      else if (EPIPE == errno)
      {
        PD_LOG(DEBUG, "peer close tcp, peer=[%s]", pd_socket_str_peer(tcp_ioc->base_ioc.sock));
        pd_tcp_on_error((struct PdIOComponent*)tcp_ioc);
        ret = PD_ERR_IOC_DESTROY;
        break;
      }
      else
      {
        break;
      }
    }
    if (0 < writelen)
    {
      pd_ringbuffer_consume(&tcp_ioc->post_buf, writelen);
      PD_LOG(DEBUG, "write to peer=[%s], writelen=%d consumer_length=%d",
          pd_socket_str_peer(tcp_ioc->base_ioc.sock),
          writelen,
          pd_ringbuffer_get_producer_length(&tcp_ioc->post_buf));
    }
  }
  return ret;
}

static void pd_tcp_handle_packet(struct PdTcpIOComponent *tcp_ioc)
{
  while (1)
  {
    char *buffer = pd_ringbuffer_get_consumer_buffer(&tcp_ioc->recv_buf);
    int length = pd_ringbuffer_get_consumer_length(&tcp_ioc->recv_buf);
    if (NULL == buffer
        || 0 >= length)
    {
      break;
    }
    int handlelen = pd_transport_handle_packet(tcp_ioc->base_ioc.ts, tcp_ioc, buffer, length);
    if (0 >= handlelen)
    {
      break;
    }
    pd_ringbuffer_consume(&tcp_ioc->recv_buf, handlelen);
  }
}

int pd_tcp_on_readable(struct PdIOComponent *ioc)
{
  int ret = 0;
  if (NULL == ioc)
  {
    PD_LOG(WARN, "ioc null pointer");
  }
  else if (NULL == ioc->sock)
  {
    PD_LOG(WARN, "sock null pointer");
  }
  else
  {
    ret = pd_tcp_read_stream((struct PdTcpIOComponent*)ioc);
    if (0 == ret)
    {
      pd_tcp_handle_packet((struct PdTcpIOComponent*)ioc);
    }
  }
  return ret;
}

int pd_tcp_on_writeable(struct PdIOComponent *ioc)
{
  int ret = 0;
  if (NULL == ioc)
  {
    PD_LOG(WARN, "ioc null pointer");
  }
  else if (NULL == ioc->sock)
  {
    PD_LOG(WARN, "sock null pointer");
  }
  else
  {
    ret = pd_tcp_write_stream((struct PdTcpIOComponent*)ioc);
  }
  return ret;
}

void pd_tcp_on_error(struct PdIOComponent *ioc)
{
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
  else if (0 != pd_transport_remove_ioc(ioc->ts, ioc))
  {
    PD_LOG(WARN, "pd_transport_remove_ioc fail, ioc=%p", ioc);
  }
  else
  {
    PD_LOG(DEBUG, "tcp fd error, will close, ioc=%p sock=%p", ioc, ioc->sock);
    pd_socket_destroy(ioc->sock);
    pd_tcp_ioc_free(ioc);
  }
}

struct PdIOComponent *pd_tcp_ioc_alloc()
{
  struct PdTcpIOComponent *tcp_ioc = (struct PdTcpIOComponent*)malloc(sizeof(struct PdTcpIOComponent));
  if (NULL != tcp_ioc)
  {
    memset((void*)tcp_ioc, 0, sizeof(struct PdTcpIOComponent));
    if (0 != pd_ringbuffer_init(&tcp_ioc->recv_buf)
      || 0 != pd_ringbuffer_init(&tcp_ioc->post_buf))
    {
      pd_tcp_ioc_free((struct PdIOComponent*)tcp_ioc);
      tcp_ioc = NULL;
    }
  }
  return (struct PdIOComponent*)tcp_ioc;
}

void pd_tcp_ioc_free(struct PdIOComponent *ioc)
{
  struct PdTcpIOComponent *tcp_ioc = (struct PdTcpIOComponent*)ioc;
  if (NULL != tcp_ioc)
  {
    pd_ringbuffer_destroy(&tcp_ioc->recv_buf);
    pd_ringbuffer_destroy(&tcp_ioc->post_buf);
    free(tcp_ioc);
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

int pd_tcp_post_packet(struct PdTcpIOComponent *tcp_ioc, const char *buffer, const int length)
{
  int ret = 0;
  if (NULL == tcp_ioc)
  {
    PD_LOG(WARN, "ioc null pointer");
    ret = -1;
  }
  else if (NULL == buffer
      || 0 >= length)
  {
    PD_LOG(WARN, "invalid param, buffer=%p length=%d", buffer, length);
    ret = -1;
  }
  else if (pd_ringbuffer_get_free(&tcp_ioc->post_buf) < length)
  {
    PD_LOG(WARN, "buffer not enough, length=%d free=%d", length, pd_ringbuffer_get_free(&tcp_ioc->post_buf));
    ret = -1;
  }
  else
  {
    int64_t pos = 0;
    while (pos < length)
    {
      char *post_buffer = pd_ringbuffer_get_producer_buffer(&tcp_ioc->post_buf);
      int post_length = pd_ringbuffer_get_producer_length(&tcp_ioc->post_buf);
      int copy_length = (post_length > (length - pos)) ? (length - pos) : post_length;
      if (NULL == post_buffer
          || 0 >= post_length)
      {
        PD_LOG(WARN, "buffer null, post_buffer=%p post_length=%d", post_buffer, post_length);
        ret = -1;
        break;
      }
      memcpy(post_buffer, buffer + pos, copy_length);
      pd_ringbuffer_produce(&tcp_ioc->post_buf, copy_length);
      pos += copy_length;
    }
    if (0 == ret)
    {
      pd_transport_set_ioc(tcp_ioc->base_ioc.ts, (struct PdIOComponent*)tcp_ioc, 1, 1);
    }
  }
  return ret;
}

