#ifndef PD_EVENT_H_
#define PD_EVENT_H_

#include "pd_define.h"

PD_CPP_START

struct PdIOComponent;

struct PdIOEvent
{
  int readable;
  int writeable;
  int error;
  struct PdIOComponent *ioc;
};

struct PdSocketEvent;

extern struct PdSocketEvent *pd_event_init();

extern void pd_event_destroy(struct PdSocketEvent *ev);

extern int pd_event_set_event(struct PdSocketEvent *ev, struct PdIOComponent *ioc, int enable_read, int enable_write);

extern int pd_event_remove_event(struct PdSocketEvent *ev, struct PdIOComponent *ioc);

extern int pd_event_get_events(struct PdSocketEvent *ev, int timeout_us, struct PdIOEvent *events, int events_cnt);

PD_CPP_END

#endif
