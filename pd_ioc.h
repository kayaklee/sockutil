#ifndef PD_IOC_H_
#define PD_IOC_H_

#include "pd_define.h"

PD_CPP_START

struct PdIOComponent;
struct PdSocket;
struct PdTransport;

typedef int (*pd_on_readable_pt) (struct PdIOComponent *ioc);
typedef int (*pd_on_writeable_pt) (struct PdIOComponent *ioc);
typedef void (*pd_on_error_pt) (struct PdIOComponent *ioc);

struct PdIOComponent
{
  struct PdSocket *sock;
  struct PdTransport *ts;
  pd_on_readable_pt on_readable;
  pd_on_writeable_pt on_writeable;
  pd_on_error_pt on_error;
  int in_epoll_read;
  int in_epoll_write;
  int tmp_pos;
  char tmp_buf[PD_MAX_PACKET_LENGTH];
};

PD_CPP_END

#endif

