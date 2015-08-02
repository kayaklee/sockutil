#ifndef PD_SOCKET_H_
#define PD_SOCKET_H_

#include <netinet/in.h>
#include <sys/types.h>
#include "pd_define.h"

PD_CPP_START

struct PdSocket;

enum PdSocketType
{
  PD_SOCK_TCP = SOCK_STREAM,
  PD_SOCK_UDP = SOCK_DGRAM,
};

////////////////////////////////////////////////////////////////////////////////////////////////////

extern const char *pd_socket_str_ip(uint32_t ip);

extern const char *pd_socket_str_ad(struct sockaddr_in *addr);

extern int pd_socket_get_port(struct sockaddr_in *addr);

extern int pd_socket_get_ip(struct sockaddr_in *addr);

////////////////////////////////////////////////////////////////////////////////////////////////////

extern struct PdSocket *pd_socket_init(enum PdSocketType type);

extern void pd_socket_destroy(struct PdSocket *sock);

extern int pd_socket_get_fd(struct PdSocket *sock);

extern struct sockaddr_in *pd_socket_get_addr(struct PdSocket *sock);

extern struct sockaddr_in *pd_socket_get_peer(struct PdSocket *sock);

////////////////////////////////////////////////////////////////////////////////////////////////////

extern int pd_socket_set_addr(struct PdSocket *sock, const char *addr, int port);

extern int pd_socket_set_peer(struct PdSocket *sock, const char *addr, int port);

extern int pd_socket_connect(struct PdSocket *sock);

extern int pd_socket_bind_addr(struct PdSocket *sock);

extern int pd_socket_bind_peer(struct PdSocket *sock);

extern int pd_socket_listen(struct PdSocket *sock, int backlog);

extern struct PdSocket *pd_socket_accept(struct PdSocket *sock);

extern void pd_socket_close(struct PdSocket *sock);

////////////////////////////////////////////////////////////////////////////////////////////////////

extern const char *pd_socket_str_addr(struct PdSocket *sock);

extern const char *pd_socket_str_peer(struct PdSocket *sock);

extern int pd_socket_int_option(struct PdSocket *sock, int type, int option, int value);

extern int pd_socket_time_option(struct PdSocket *sock, int option, int64_t usec);

////////////////////////////////////////////////////////////////////////////////////////////////////

extern int pd_socket_keep_alive(struct PdSocket *sock, int on);

extern int pd_socket_reuse_addr(struct PdSocket *sock, int on);

extern int pd_socket_linger(struct PdSocket *sock, int on, int sec);

extern int pd_socket_tcp_nodelay(struct PdSocket *sock, int on);

extern int pd_socket_tcp_quickack(struct PdSocket *sock, int on);

extern int pd_socket_no_blocking(struct PdSocket *sock, int on);

extern int pd_socket_send_buffer(struct PdSocket *sock, int size);

extern int pd_socket_recv_buffer(struct PdSocket *sock, int size);

extern int pd_socket_send_timeo(struct PdSocket *sock, int time);

extern int pd_socket_recv_timeo(struct PdSocket *sock, int time);

////////////////////////////////////////////////////////////////////////////////////////////////////

extern struct PdSocket *pd_socket_init_tcp_server(int port);

extern struct PdSocket *pd_socket_init_tcp_client(const char *addr, int port);

extern struct PdSocket *pd_socket_accept_tcp_client(struct PdSocket *listen_sock);

extern struct PdSocket *pd_socket_init_udp_server(int port);

extern struct PdSocket *pd_socket_init_udp_client(const char *addr, int port);

PD_CPP_END

#endif

