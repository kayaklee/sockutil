#ifndef PD_ACCEPTER_H_
#define PD_ACCEPTER_H_

#include "pd_define.h"

PD_CPP_START

struct PdIOComponent;

extern int pd_listen_on_readable(struct PdIOComponent *ioc);

extern int pd_listen_on_writeable(struct PdIOComponent *ioc);

extern void pd_listen_on_error(struct PdIOComponent *ioc);

PD_CPP_END

#endif

