#ifndef PD_TRANSPORT_H_
#define PD_TRANSPORT_H_

#include "pd_define.h"

PD_CPP_START

struct PdTcpIOComponent;
struct PdIOComponent;
struct PdTransport;

typedef void (*pd_on_interval_pt) (void *arg);
typedef int (*pd_handle_packet_pt) (struct PdTcpIOComponent *tcp_ioc, void *arg, const char *buffer, const int length);

extern struct PdTransport *pd_transport_init(const int64_t bind_core_id);

extern void pd_transport_destroy(struct PdTransport *ts);

extern void pd_transport_set_timer(struct PdTransport *ts, pd_on_interval_pt on_interval, void *arg);

extern void pd_transport_set_handler(struct PdTransport *ts, pd_handle_packet_pt handle_packet, void *arg);

extern int pd_transport_run(struct PdTransport *ts);

extern int pd_transport_stop(struct PdTransport *ts);

extern int pd_transport_wait(struct PdTransport *ts);

extern int pd_transport_set_ioc(struct PdTransport *ts, struct PdIOComponent *ioc, int enable_read, int enable_write);

extern int pd_transport_remove_ioc(struct PdTransport *ts, struct PdIOComponent *ioc);

////////////////////////////////////////////////////////////////////////////////////////////////////

extern int pd_transport_handle_packet(struct PdTransport *ts, struct PdTcpIOComponent *tcp_ioc, const char *buffer, const int length);

PD_CPP_END

#endif
