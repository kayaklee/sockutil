#include <assert.h>
#include <string.h>
#include "pd_define.h"
#include "pd_log.h"
#include "pd_transport.h"
#include "pd_socket.h"
#include "pd_ioc.h"
#include "pd_tcp.h"
#include "pd_accepter.h"

struct P2PInfo
{
  int ip[2];
  int port[2];
};

struct P2PInfo g_p2p_info;

static int handle_packet(struct PdTcpIOComponent *tcp_ioc, void *arg, const char *buffer, const int length)
{
  struct PdIOComponent *ioc = (struct PdIOComponent *)tcp_ioc;
  int port = pd_socket_get_port(pd_socket_get_peer(ioc->sock));
  int ip = pd_socket_get_ip(pd_socket_get_peer(ioc->sock));

  const int *number = (const int *)buffer;
  PD_LOG(INFO, "port=%d ip=%s number=%d", port, pd_socket_str_ip(ip), *number);

  if (0 <= *number
      && 2 > *number) {
    g_p2p_info.ip[*number] = ip;
    g_p2p_info.port[*number] = port;
    pd_tcp_post_packet(tcp_ioc, (char*)&g_p2p_info, sizeof(g_p2p_info));
  }
  return length;
}

int main(int argc, char **argv)
{
  memset(&g_p2p_info, 0, sizeof(g_p2p_info));

  if (2 > argc)
  {
    fprintf(stderr, "./server port\n");
    exit(-1);
  }
  pd_bind_core(0);

  int port = atoi(argv[1]);

  struct PdTransport *transport = pd_transport_init(-1);
  assert(NULL != transport);
  pd_transport_set_handler(transport, handle_packet, NULL);

  struct PdSocket *listen_sock = pd_socket_init_tcp_server(port);
  assert(NULL != listen_sock);

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
  pd_transport_wait(transport);

  pd_tcp_ioc_free(listen_ioc);
  listen_ioc = NULL;
  pd_socket_destroy(listen_sock);
  listen_sock = NULL;
  pd_transport_destroy(transport);
  transport = NULL;
}

