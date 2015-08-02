#include <assert.h>
#include "pd_define.h"
#include "pd_log.h"
#include "pd_socket.h"

int main(int argc, char **argv)
{
  if (3 > argc)
  {
    fprintf(stderr, "./client addr port\n");
    exit(-1);
  }

  const char *addr = argv[1];
  int port = atoi(argv[2]);

  struct PdSocket *sock = pd_socket_init_tcp_client(addr, port);
  assert(NULL != sock);
  pd_socket_close(sock);
}

