#include "pd_udp_server.h"
#include "pd_socket.h"
#include "pd_log.h"
#include "pd_tcp.h"
#include "pd_ioc.h"
#include "pd_transport.h"

int pd_udp_server_on_readable(struct PdIOComponent *ioc)
{
  int ret = 0;
  struct PdUDPPacket recv_pkt;
  struct PdUDPPacket send_pkt;
  struct sockaddr_in peer;
  int len = sizeof(struct sockaddr);
  int recv_size = 0;
  int send_size = 0;
  if (NULL == ioc)
  {
    PD_LOG(WARN, "ioc null pointer");
  }
  else if (NULL == ioc->sock)
  {
    PD_LOG(WARN, "sock null pointer");
  }
  else if (-1 == (recv_size = recvfrom(pd_socket_get_fd(ioc->sock), &recv_pkt, sizeof(recv_pkt), 0, (struct sockaddr *)&peer, (socklen_t *)&len)))
  {
    PD_LOG(WARN, "recvfrom sock fail, upd_server_sock=%p", ioc->sock);
  }
  else
  {
    send_pkt.send_timestamp_ = pd_get_time();
    send_pkt.peer_ = peer;
    if (-1 == (send_size = sendto(pd_socket_get_fd(ioc->sock), &send_pkt, sizeof(send_pkt), 0, &peer, len)))
    {
      PD_LOG(WARN, "sendto sock fail, upd_server_sock=%p", ioc->sock);
    }
    else
    {
      int64_t timeu = send_pkt.send_timestamp_ - recv_pkt.send_timestamp_;
      PD_LOG(INFO, "recvfrom succ, udp_server_fd=%d udp_server_addr=[%s] peer_addr=[%s] timeu=%ld",
          pd_socket_get_fd(ioc->sock), pd_socket_str_ad(pd_socket_get_addr(ioc->sock)), pd_socket_str_ad(&peer), timeu);
    }
  }
  return ret;
}

int pd_udp_server_on_writeable(struct PdIOComponent *ioc)
{
  int ret = 0;
  PD_LOG(FATAL, "unexpected error, udp server fd cannot be writeable, ioc=%p", ioc);
  return ret;
}

void pd_udp_server_on_error(struct PdIOComponent *ioc)
{
  PD_LOG(FATAL, "unexpected error, udp server fd cannot be error, ioc=%p", ioc);
}

