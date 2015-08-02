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

  struct PdSocket *sock = pd_socket_init_udp_client(addr, port);
  assert(NULL != sock);

  struct PdUDPPacket send_pkt;
  struct PdUDPPacket recv_pkt;
  send_pkt.send_timestamp_ = pd_get_time();
  int send_size = send(pd_socket_get_fd(sock), &send_pkt, sizeof(send_pkt), 0);
  assert(sizeof(send_pkt) == send_size);

  int recv_size = recv(pd_socket_get_fd(sock), &recv_pkt, sizeof(recv_pkt), 0);
  assert(sizeof(recv_pkt) == recv_size);

  int64_t timeu = pd_get_time() - send_pkt.send_timestamp_;
  PD_LOG(INFO, "recv succ, udp_fd=%d udp_server_addr=[%s] self_addr=[%s] timeu=%ld",
      pd_socket_get_fd(sock), pd_socket_str_ad(pd_socket_get_addr(sock)), pd_socket_str_ad(&(recv_pkt.peer_)), timeu);

  pd_socket_close(sock);
}

