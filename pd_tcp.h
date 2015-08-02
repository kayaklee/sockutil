#ifndef PD_TCP_H_
#define PD_TCP_H_

#include "pd_define.h"

PD_CPP_START

struct PdIOComponent;
struct PdTcpIOComponent;

extern int pd_tcp_on_readable(struct PdIOComponent *ioc);

extern int pd_tcp_on_writeable(struct PdIOComponent *ioc);

extern void pd_tcp_on_error(struct PdIOComponent *ioc);

extern struct PdIOComponent *pd_tcp_ioc_alloc();

extern void pd_tcp_ioc_free(struct PdIOComponent *ioc);

////////////////////////////////////////////////////////////////////////////////////////////////////

extern int pd_tcp_post_packet(struct PdTcpIOComponent *tcp_ioc, const char *buffer, const int length);

PD_CPP_END

#endif

