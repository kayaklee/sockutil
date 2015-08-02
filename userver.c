#include <assert.h>
#include "pd_define.h"
#include "pd_log.h"
#include "pd_transport.h"
#include "pd_socket.h"
#include "pd_ioc.h"
#include "pd_tcp.h"
#include "pd_udp_server.h"

int main(int argc, char **argv)
{
  if (2 > argc)
  {
    fprintf(stderr, "./userver port\n");
    exit(-1);
  }
  pd_bind_core(0);

  int port = atoi(argv[1]);

  struct PdTransport *transport = pd_transport_init(-1);
  assert(NULL != transport);

  struct PdSocket *listen_sock = pd_socket_init_udp_server(port);
  assert(NULL != listen_sock);

  struct PdIOComponent *listen_ioc = pd_tcp_ioc_alloc();
  assert(NULL != listen_ioc);

  listen_ioc->sock = listen_sock;
  listen_ioc->ts = transport;
  listen_ioc->on_readable = pd_udp_server_on_readable;
  listen_ioc->on_writeable = pd_udp_server_on_writeable;
  listen_ioc->on_error = pd_udp_server_on_error;
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

