#include <assert.h>
#include <errno.h>
#include "pd_define.h"
#include "pd_log.h"
#include "pd_socket.h"
#include "pd_transport.h"
#include "pd_ioc.h"
#include "pd_tcp.h"
#include "pd_accepter.h"

struct P2PInfo
{
  int ip[2];
  int port[2];
};

int main(int argc, char **argv)
{
  if (4 > argc)
  {
    fprintf(stderr, "./client addr port number\n");
    exit(-1);
  }

  const char *addr = argv[1];
  int port = atoi(argv[2]);
  int number = atoi(argv[3]);
  number = number % 2;

  struct PdSocket *sock = pd_socket_init_tcp_client(addr, port);
  assert(NULL != sock);

  int ret = pd_socket_reuse_addr(sock, 1);
  assert(0 == ret);

  int listen_port = pd_socket_get_port(pd_socket_get_peer(sock));
  int listen_ip = pd_socket_get_ip(pd_socket_get_peer(sock));
  PD_LOG(INFO, "listen_port=%d listen_ip=%s", listen_port, pd_socket_str_ip(listen_ip));

  int peer_ip = 0;
  int peer_port = 0;
  pd_socket_no_blocking(sock, 0);
  while (1) {
    int64_t write_ret = write(pd_socket_get_fd(sock), &number, sizeof(number));
    assert(sizeof(number) == write_ret);
    struct P2PInfo p2p_info;
    int64_t read_ret = read(pd_socket_get_fd(sock), &p2p_info, sizeof(p2p_info));
    assert(sizeof(p2p_info) == read_ret);
    PD_LOG(INFO, "ip0=%s port0=%d ip1=%s port1=%d",
        pd_socket_str_ip(p2p_info.ip[0]),
        p2p_info.port[0],
        pd_socket_str_ip(p2p_info.ip[1]),
        p2p_info.port[1]);
    if (p2p_info.ip[1 - number] != 0) {
      peer_ip = p2p_info.ip[1 - number];
      peer_port = p2p_info.port[1 - number];
      break;
    }
    usleep(1000000);
  }
  //pd_socket_close(sock);

  ////////////////////////////////////////////////////////////////////////////////////////////////////
  
  struct PdSocket *peer_client = pd_socket_init(PD_SOCK_TCP);
  if (NULL != peer_client)
  {
    if (0 != pd_socket_set_addr(peer_client, pd_socket_str_ip(peer_ip), peer_port)
        || 0 != pd_socket_set_peer(peer_client, NULL, listen_port)
        || 0 != pd_socket_reuse_addr(peer_client, 1)
        || 0 != pd_socket_bind_peer(peer_client))
    {
      pd_socket_destroy(peer_client);
      peer_client = NULL;
    }
  }

  struct PdSocket *listen_sock = pd_socket_init_tcp_server(listen_port);
  assert(NULL != listen_sock);
  
  struct PdTransport *transport = pd_transport_init(-1);
  assert(NULL != transport);

  struct PdIOComponent *listen_ioc = pd_tcp_ioc_alloc();
  assert(NULL != listen_ioc);

  listen_ioc->sock = listen_sock;
  listen_ioc->ts = transport;
  listen_ioc->on_readable = pd_listen_on_readable;
  listen_ioc->on_writeable = pd_listen_on_writeable;
  listen_ioc->on_error = pd_listen_on_error;
  listen_ioc->in_epoll_read = 0;
  listen_ioc->in_epoll_write = 0;
  listen_ioc->tmp_pos = 0;
  if (0 != pd_transport_set_ioc(transport, listen_ioc, 1, 0))
  {
    PD_LOG(WARN, "pd_transport_set_ioc fail, listen_ioc=%p", listen_ioc);
    pd_tcp_ioc_free(listen_ioc);
    listen_ioc = NULL;
    pd_socket_destroy(listen_sock);
    listen_sock = NULL;
  }

  pd_transport_run(transport);

  int64_t i = 0;
  for (i = 0; i < 100; i++) {
    ret = pd_socket_connect(peer_client);
    if (0 == ret) {
      break;
    }
    if (EADDRNOTAVAIL == errno) {
      ret = 0;
      break;
    }
    usleep(100000);
  }
  assert(0 == ret);

  pd_transport_wait(transport);

  pd_tcp_ioc_free(listen_ioc);
  listen_ioc = NULL;
  pd_socket_destroy(listen_sock);
  listen_sock = NULL;
  pd_transport_destroy(transport);
  transport = NULL;
}
