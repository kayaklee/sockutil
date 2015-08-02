#ifndef PD_UDP_SERVER_H_
#define PD_UDP_SERVER_H_

#include "pd_define.h"

PD_CPP_START

struct PdIOComponent;

extern int pd_udp_server_on_readable(struct PdIOComponent *ioc);

extern int pd_udp_server_on_writeable(struct PdIOComponent *ioc);

extern void pd_udp_server_on_error(struct PdIOComponent *ioc);

PD_CPP_END

#endif

