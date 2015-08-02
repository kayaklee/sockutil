#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pd_socket.h"
#include "pd_log.h"

struct PdSocket
{
  int fd;
  struct sockaddr_in addr;
  struct sockaddr_in peer;
};

static struct PdSocket *alloc_();

static void free_(struct PdSocket *sock);

static int is_ip_addr_(const char *addr);

////////////////////////////////////////////////////////////////////////////////////////////////////

struct PdSocket *alloc_()
{
  struct PdSocket *ret = (struct PdSocket*)malloc(sizeof(struct PdSocket));
  if (NULL != ret)
  {
    memset(ret, 0, sizeof(*ret));
    ret->fd = -1;
  }
  return ret;
}

void free_(struct PdSocket *sock)
{
  if (NULL != sock)
  {
    free(sock);
  }
}

int is_ip_addr_(const char *addr)
{
  int ret = 1;
  char c = '\0';
  const char *p = addr;
  while ('\0' != (c = (*p++)))
  {
    if ('.' != c
        && (!('0' <= c && c <= '9')))
    {
      ret = 0;
      break;
    }
  }
  return ret;
}

const char *pd_socket_str_ip(uint32_t ip)
{
  static __thread char buffers[4][16];
  static __thread int32_t i = 0;
  char *buffer = buffers[i++ % 4];
  snprintf(buffer, 16, "%d.%d.%d.%d",
      (ip >> 24) & 255,
      (ip >> 16) & 255,
      (ip >> 8) & 255,
      (ip) & 255);
  return buffer;
}

const char *pd_socket_str_ad(struct sockaddr_in *addr)
{
  static __thread char buffers[4][32];
  static __thread int32_t i = 0;
  char *buffer = NULL;
  if (NULL != addr)
  {
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    int32_t port = ntohs(addr->sin_port);
    buffer = buffers[i++ % 4];
    snprintf(buffer, 32, "%d.%d.%d.%d:%d",
        (ip >> 24) & 255,
        (ip >> 16) & 255,
        (ip >> 8) & 255,
        (ip) & 255,
        port);
  }
  return buffer;
}

int pd_socket_get_port(struct sockaddr_in *addr)
{
  int ret = -1;
  if (NULL != addr) {
    ret = ntohs(addr->sin_port);
  }
  return ret;
}

int pd_socket_get_ip(struct sockaddr_in *addr)
{
  int ret = 0;
  if (NULL != addr)
  {
    ret = ntohl(addr->sin_addr.s_addr);
  }
  return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

struct PdSocket *pd_socket_init(enum PdSocketType type)
{
  struct PdSocket *ret = NULL;
  if (NULL == (ret = alloc_()))
  {
    PD_LOG(WARN, "alloc struct PdSocket fail");
  }
  else if (-1 == (ret->fd = socket(AF_INET, type, 0)))
  {
    PD_LOG(WARN, "create socket fd fail, errno=%u", errno);
    free_(ret);
    ret = NULL;
  }
  else
  {
    PD_LOG(DEBUG, "create socket fd succ, type=%d fd=%d", type, ret->fd);
  }
  return ret;
}

void pd_socket_destroy(struct PdSocket *sock)
{
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
  }
  else
  {
    pd_socket_close(sock);
    free_(sock);
  }
}

int pd_socket_get_fd(struct PdSocket *sock)
{
  int ret = -1;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    PD_BACKTRACE("socket null");
  }
  else
  {
    ret = sock->fd;
  }
  return ret;
}

struct sockaddr_in *pd_socket_get_addr(struct PdSocket *sock)
{
  struct sockaddr_in *ret = NULL;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
  }
  else
  {
    ret = &(sock->addr);
  }
  return ret;
}

struct sockaddr_in *pd_socket_get_peer(struct PdSocket *sock)
{
  struct sockaddr_in *ret = NULL;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
  }
  else
  {
    ret = &(sock->peer);
  }
  return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void pd_socket_close(struct PdSocket *sock)
{
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
  }
  else
  {
    if (-1 != sock->fd)
    {
      PD_LOG(DEBUG, "close socket, fd=%d", sock->fd);
      close(sock->fd);
      sock->fd = -1;
    }
  }
}

int pd_socket_set_addr(struct PdSocket *sock, const char *addr, int port)
{
  int ret = 0;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    ret = -1;
  }
  else
  {
    memset(&(sock->addr), 0, sizeof(sock->addr));
    sock->addr.sin_family = AF_INET;
    sock->addr.sin_port = htons(port);

    if (NULL == addr
        || '\0' == addr[0])
    {
      sock->addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else if (is_ip_addr_(addr))
    {
      sock->addr.sin_addr.s_addr = inet_addr(addr);
    }
    else
    {
      static const uint32_t BUFFER_SIZE = 4096;
      char buffer[BUFFER_SIZE];
      struct hostent hostinfo;
      struct hostent *phost = NULL;
      if (0 != gethostbyname_r(addr, &hostinfo, buffer, BUFFER_SIZE, &phost, &ret))
      {
        PD_LOG(WARN, "gethostbyname_r fail, addr=[%s] errno=%u", addr, h_errno);
        ret = -1;
      }
      else
      {
        memcpy(&(sock->addr.sin_addr), *(hostinfo.h_addr_list), sizeof(struct in_addr));
        PD_LOG(DEBUG, "trans name to ip succ, addr=[%s] ip=[%s]",
            addr, pd_socket_str_ip(ntohl(sock->addr.sin_addr.s_addr)));
      }
    }
    if (0 == ret)
    {
      PD_LOG(DEBUG, "set addr succ, addr=[%s]",
          pd_socket_str_ad(&sock->addr));
    }
  }
  return ret;
}

int pd_socket_set_peer(struct PdSocket *sock, const char *addr, int port)
{
  int ret = 0;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    ret = -1;
  }
  else
  {
    memset(&(sock->peer), 0, sizeof(sock->peer));
    sock->peer.sin_family = AF_INET;
    sock->peer.sin_port = htons(port);

    if (NULL == addr
        || '\0' == addr[0])
    {
      sock->peer.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else if (is_ip_addr_(addr))
    {
      sock->peer.sin_addr.s_addr = inet_addr(addr);
    }
    else
    {
      static const uint32_t BUFFER_SIZE = 4096;
      char buffer[BUFFER_SIZE];
      struct hostent hostinfo;
      struct hostent *phost = NULL;
      if (0 != gethostbyname_r(addr, &hostinfo, buffer, BUFFER_SIZE, &phost, &ret))
      {
        PD_LOG(WARN, "gethostbyname_r fail, addr=[%s] errno=%u", addr, h_errno);
        ret = -1;
      }
      else
      {
        memcpy(&(sock->peer.sin_addr), *(hostinfo.h_addr_list), sizeof(struct in_addr));
        PD_LOG(DEBUG, "trans name to ip succ, addr=[%s] ip=[%s]",
            addr, pd_socket_str_ip(ntohl(sock->peer.sin_addr.s_addr)));
      }
    }
    if (0 == ret)
    {
      PD_LOG(DEBUG, "set peer succ, addr=[%s]",
          pd_socket_str_ad(&sock->peer));
    }
  }
  return ret;
}

int pd_socket_connect(struct PdSocket *sock)
{
  int ret = 0;
  int64_t timeu = pd_get_time();
  int len = sizeof(struct sockaddr);
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    ret = -1;
  }
  else if (0 != connect(sock->fd, (struct sockaddr *)&sock->addr, sizeof(sock->addr)))
  {
    PD_LOG(WARN, "connect fail, errno=%u fd=%d addr=%s",
        errno, sock->fd, pd_socket_str_ad(&sock->addr));
    ret = -1;
  }
  else if (0 != getsockname(sock->fd, (struct sockaddr *)&sock->peer, (socklen_t *)&len))
  {
    PD_LOG(WARN, "getsockname fail, errno=%u fd=%d addr=%s",
        errno, sock->fd, pd_socket_str_ad(&sock->peer));
    ret = -1;
  }
  else
  {
    timeu = pd_get_time() - timeu;
    PD_LOG(INFO, "connect succ, fd=%d addr=%s peer=%s timeu=%ld",
        sock->fd, pd_socket_str_ad(&sock->addr), pd_socket_str_ad(&sock->peer), timeu);
  }
  return ret;
}

int pd_socket_bind_addr(struct PdSocket *sock)
{
  int ret = 0;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    ret = -1;
  }
  else if ((0 != sock->addr.sin_port || 0 != sock->addr.sin_addr.s_addr)
      && 0 != bind(sock->fd, (struct sockaddr *)&sock->addr, sizeof(sock->addr)))
  {
    PD_LOG(WARN, "bind addr fail, errno=%u fd=%d addr=%s",
        errno, sock->fd, pd_socket_str_ad(&sock->addr));
    ret = -1;
  }
  else
  {
    PD_LOG(INFO, "bind succ, fd=%d addr=%s",
        sock->fd, pd_socket_str_ad(&sock->addr));
  }
  return ret;
}

int pd_socket_bind_peer(struct PdSocket *sock)
{
  int ret = 0;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    ret = -1;
  }
  else if ((0 != sock->peer.sin_port || 0 != sock->peer.sin_addr.s_addr)
      && 0 != bind(sock->fd, (struct sockaddr *)&sock->peer, sizeof(sock->peer)))
  {
    PD_LOG(WARN, "bind peer fail, errno=%u fd=%d peer=%s",
        errno, sock->fd, pd_socket_str_ad(&sock->peer));
    ret = -1;
  }
  else
  {
    PD_LOG(INFO, "bind succ, fd=%d peer=%s",
        sock->fd, pd_socket_str_ad(&sock->peer));
  }
  return ret;
}

int pd_socket_listen(struct PdSocket *sock, int backlog)
{
  int ret = 0;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    ret = -1;
  }
  else if (0 != listen(sock->fd, backlog))
  {
    PD_LOG(WARN, "listen fail, errno=%u backlog=%d fd=%d addr=%s",
        errno, backlog, sock->fd, pd_socket_str_ad(&sock->addr));
    ret = -1;
  }
  else
  {
    PD_LOG(INFO, "listen succ, backlog=%d fd=%d addr=%s",
        backlog, sock->fd, pd_socket_str_ad(&sock->addr));
  }
  return ret;
}

struct PdSocket *pd_socket_accept(struct PdSocket *sock)
{
  struct PdSocket *ret = NULL;
  int len = sizeof(struct sockaddr);
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
  }
  else if (NULL == (ret = alloc_()))
  {
    PD_LOG(WARN, "alloc struct PdSocket fail");
  }
  else if (-1 == (ret->fd = accept(sock->fd, (struct sockaddr*)&(ret->peer), (socklen_t *)&len)))
  {
    PD_LOG(WARN, "accept fail, errno=%u listen_fd=%d accept_fd=%d listen_addr=[%s] peer_addr=[%s]",
        errno, sock->fd, ret->fd, pd_socket_str_ad(&(sock->addr)), pd_socket_str_ad(&(ret->peer)));
    free_(ret);
    ret = NULL;
  }
  else if (0 != getsockname(ret->fd, (struct sockaddr *)&ret->addr, (socklen_t *)&len))
  {
    PD_LOG(WARN, "getsockname fail, errno=%u fd=%d addr=%s",
        errno, ret->fd, pd_socket_str_ad(&ret->addr));
    pd_socket_destroy(ret);
    ret = NULL;
  }
  else
  {
    PD_LOG(INFO, "accept succ, listen_fd=%d accept_fd=%d listen_addr=[%s] "
        "local_addr=[%s] peer_addr=[%s]",
        sock->fd, ret->fd, pd_socket_str_ad(&(sock->addr)),
        pd_socket_str_ad(&(ret->addr)), pd_socket_str_ad(&(ret->peer)));
  }
  return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

const char *pd_socket_str_addr(struct PdSocket *sock)
{
  const char *ret = NULL;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
  }
  else
  {
    return pd_socket_str_ad(&(sock->addr));
  }
  return ret;
}

const char *pd_socket_str_peer(struct PdSocket *sock)
{
  const char *ret = NULL;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
  }
  else
  {
    ret = pd_socket_str_ad(&(sock->peer));
  }
  return ret;
}

int pd_socket_int_option(struct PdSocket *sock, int type, int option, int value)
{
  int ret = 0;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    ret = -1;
  }
  else if (0 != setsockopt(sock->fd, type, option, (void*)&value, sizeof(value)))
  {
    PD_LOG(WARN, "setsockopt fail, errno=%u fd=%d option=%d value=%d",
        errno, sock->fd, option, value);
    ret = -1;
  }
  else
  {
    PD_LOG(DEBUG, "setsockopt succ, fd=%d option=%d value=%d",
        sock->fd, option, value);
  }
  return ret;
}

int pd_socket_time_option(struct PdSocket *sock, int option, int64_t usec)
{
  int ret = 0;
  struct timeval tv;
  tv.tv_sec = (int)(usec / 1000000);
  tv.tv_usec = (int)(usec % 1000000);
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    ret = -1;
  }
  else if (0 != setsockopt(sock->fd, SOL_SOCKET, option, (void*)&tv, sizeof(tv)))
  {
    PD_LOG(WARN, "setsockopt fail, errno=%u fd=%d option=%d value=%ld",
        errno, sock->fd, option, usec);
    ret = -1;
  }
  else
  {
    PD_LOG(DEBUG, "setsockopt succ, fd=%d option=%d value=%ld",
        sock->fd, option, usec);
  }
  return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

int pd_socket_keep_alive(struct PdSocket *sock, int on)
{
  return pd_socket_int_option(sock, SOL_SOCKET, SO_KEEPALIVE, on);
}

int pd_socket_reuse_addr(struct PdSocket *sock, int on)
{
  return pd_socket_int_option(sock, SOL_SOCKET, SO_REUSEADDR, on);
}

int pd_socket_linger(struct PdSocket *sock, int on, int sec)
{
  int ret = 0;
  struct linger lt;
  lt.l_onoff = on;
  lt.l_linger = sec;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    ret = -1;
  }
  else if (0 != setsockopt(sock->fd, SOL_SOCKET, SO_LINGER, (void*)&lt, sizeof(lt)))
  {
    PD_LOG(WARN, "setsockopt linger fail, errno=%u fd=%d value=%d",
        errno, sock->fd, sec);
    ret = -1;
  }
  else
  {
    PD_LOG(DEBUG, "setsockopt linger succ, fd=%d value=%d",
        sock->fd, sec);
  }
  return ret;
}

int pd_socket_tcp_nodelay(struct PdSocket *sock, int on)
{
  return pd_socket_int_option(sock, IPPROTO_TCP, TCP_NODELAY, on);
}

int pd_socket_tcp_quickack(struct PdSocket *sock, int on)
{
  return pd_socket_int_option(sock, IPPROTO_TCP, TCP_QUICKACK, on);
}

int pd_socket_no_blocking(struct PdSocket *sock, int on)
{
  int ret = 0;
  int flag = 0;
  if (NULL == sock)
  {
    PD_LOG(WARN, "socket null pointer");
    ret = -1;
  }
  else if (0 >= (flag = fcntl(sock->fd, F_GETFL, NULL)))
  {
    PD_LOG(WARN, "fcntl F_GETFL fail, errno=%u fd=%d", errno, sock->fd);
    ret = -1;
  }
  else
  {
    if (on)
    {
      flag |= O_NONBLOCK;
    }
    else
    {
      flag &= ~O_NONBLOCK;
    }
    if (0 != fcntl(sock->fd, F_SETFL, flag))
    {
      PD_LOG(WARN, "fcntl F_SETFL fail, errno=%u fd=%d", errno, sock->fd);
      ret = -1;
    }
    else
    {
      PD_LOG(DEBUG, "fcntl F_SETFL succ, fd=%d flag=%d", sock->fd, flag);
    }
  }
  return ret;
}

int pd_socket_send_buffer(struct PdSocket *sock, int size)
{
  return pd_socket_int_option(sock, SOL_SOCKET, SO_SNDBUF, size);
}

int pd_socket_recv_buffer(struct PdSocket *sock, int size)
{
  return pd_socket_int_option(sock, SOL_SOCKET, SO_RCVBUF, size);
}

int pd_socket_send_timeo(struct PdSocket *sock, int time)
{
  return pd_socket_time_option(sock, SO_SNDTIMEO, time);
}

int pd_socket_recv_timeo(struct PdSocket *sock, int time)
{
  return pd_socket_time_option(sock, SO_RCVTIMEO, time);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

struct PdSocket *pd_socket_init_tcp_server(int port)
{
  struct PdSocket *ret = pd_socket_init(PD_SOCK_TCP);
  if (NULL != ret)
  {
    if (0 != pd_socket_set_addr(ret, NULL, port)
        || 0 != pd_socket_reuse_addr(ret, 1)
        || 0 != pd_socket_keep_alive(ret, 1)
        || 0 != pd_socket_linger(ret, 1, 10)
        //|| 0 != pd_socket_tcp_nodelay(ret, 1)
        || 0 != pd_socket_tcp_quickack(ret, 1)
        || 0 != pd_socket_no_blocking(ret, 1)
        || 0 != pd_socket_send_buffer(ret, PD_SOCKET_BUFFER_SIZE)
        || 0 != pd_socket_recv_buffer(ret, PD_SOCKET_BUFFER_SIZE)
        || 0 != pd_socket_bind_addr(ret)
        || 0 != pd_socket_listen(ret, 1024))
    {
      pd_socket_destroy(ret);
      ret = NULL;
    }
  }
  return ret;
}

struct PdSocket *pd_socket_init_tcp_client(const char *addr, int port)
{
  struct PdSocket *ret = pd_socket_init(PD_SOCK_TCP);
  if (NULL != ret)
  {
    if (0 != pd_socket_set_addr(ret, addr, port)
        || 0 != pd_socket_keep_alive(ret, 1)
        || 0 != pd_socket_linger(ret, 1, 10)
        //|| 0 != pd_socket_tcp_nodelay(ret, 1)
        || 0 != pd_socket_tcp_quickack(ret, 1)
        || 0 != pd_socket_send_buffer(ret, PD_SOCKET_BUFFER_SIZE)
        || 0 != pd_socket_recv_buffer(ret, PD_SOCKET_BUFFER_SIZE)
        || 0 != pd_socket_connect(ret))
    {
      pd_socket_destroy(ret);
      ret = NULL;
    }
    else
    {
      if (0 != pd_socket_no_blocking(ret, 1))
      {
        pd_socket_destroy(ret);
        ret = NULL;
      }
    }
  }
  return ret;
}

struct PdSocket *pd_socket_accept_tcp_client(struct PdSocket *listen_sock)
{
  struct PdSocket *ret = pd_socket_accept(listen_sock);
  if (NULL != ret)
  {
    if (0 != pd_socket_keep_alive(ret, 1)
        || 0 != pd_socket_linger(ret, 1, 10)
        //|| 0 != pd_socket_tcp_nodelay(ret, 1)
        || 0 != pd_socket_tcp_quickack(ret, 1)
        || 0 != pd_socket_no_blocking(ret, 1)
        || 0 != pd_socket_send_buffer(ret, PD_SOCKET_BUFFER_SIZE)
        || 0 != pd_socket_recv_buffer(ret, PD_SOCKET_BUFFER_SIZE))
    {
      pd_socket_destroy(ret);
      ret = NULL;
    }
  }
  return ret;
}

struct PdSocket *pd_socket_init_udp_server(int port)
{
  struct PdSocket *ret = pd_socket_init(PD_SOCK_UDP);
  if (NULL != ret)
  {
    if (0 != pd_socket_set_addr(ret, NULL, port)
        || 0 != pd_socket_reuse_addr(ret, 1)
        //|| 0 != pd_socket_no_blocking(ret, 1)
        || 0 != pd_socket_send_buffer(ret, PD_SOCKET_BUFFER_SIZE)
        || 0 != pd_socket_recv_buffer(ret, PD_SOCKET_BUFFER_SIZE)
        || 0 != pd_socket_bind_addr(ret))
    {
      pd_socket_destroy(ret);
      ret = NULL;
    }
  }
  return ret;
}

struct PdSocket *pd_socket_init_udp_client(const char *addr, int port)
{
  struct PdSocket *ret = pd_socket_init(PD_SOCK_UDP);
  if (NULL != ret)
  {
    if (0 != pd_socket_set_addr(ret, addr, port)
        || 0 != pd_socket_send_buffer(ret, PD_SOCKET_BUFFER_SIZE)
        || 0 != pd_socket_recv_buffer(ret, PD_SOCKET_BUFFER_SIZE)
        || 0 != pd_socket_connect(ret))
    {
      pd_socket_destroy(ret);
      ret = NULL;
    }
    else
    {
      // do nothing
    }
  }
  return ret;
}

