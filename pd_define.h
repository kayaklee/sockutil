#ifndef PD_DEFINE_H_
#define PD_DEFINE_H_

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <netinet/in.h>

#ifdef __cplusplus
# define PD_CPP_START extern "C" {
# define PD_CPP_END }
#else
# define PD_CPP_START
# define PD_CPP_END
#endif

#ifndef UNUSED
#define UNUSED(v) ((void)(v))
#endif

#define GETTID() syscall(__NR_gettid)
#define MAX(a,b) ((a) > (b)) ? (a) : (b)
#define MIN(a,b) ((a) < (b)) ? (a) : (b)

#define PD_MAX_SOCKET_EVENTS  256
#define PD_MAX_PACKET_LENGTH  512
#define PD_SOCKET_BUFFER_SIZE (1L<<23)
#define PD_RING_BUF_LEN (1L<<23)
#define PD_TRANSPORT_LOOP_INTERVAL  10000 //10ms
#define PD_BIGARRAY_META_LEN (1L<<22)
#define PD_BIGARRAY_ROOT_LEN (1L<<22)
#define PD_MAX_RESULT_SIZE (8L*(1L<<30))
#define PD_MAX_INTSTR_SIZE 20
#define PD_UTHREAD_STACK_SIZE 65536

#define PD_FILEWRITER_PAGEFAULT_THRESHOLD (1L<<29)
#define PD_FILEWRITER_PAGEFAULT_STEP  (1L<<22)
#define PD_FILEWRITER_WRITEBACK_THRESHOLD (1L<<29)
#define PD_FILEWRITER_WRITEBACK_STEP  (1L<<22)
#define PD_FILEWRITER_ASYNC_INTERVAL  10000
#define PD_FILEWRITER_ASYNC_TRIGGER_THRESHOLD (5L*(1L<<30))

#define PD_FILEPARSER_PAGEFAULT_STEP (1<<22)
#define PD_FILEPARSER_ASYNC_INTERVAL  10000
#define PD_FILEPARSER_ASYNC_COUNT 1

#define PD_ERR_EAGAIN     -2
#define PD_ERR_QUEUE_FULL -3
#define PD_ERR_IOC_DESTROY  -4
#define PD_ERR_ITER_END   -5
#define PD_ERR_BUF_NOT_ENOUGH -6
#define PD_ERR_TOTAL_SIZE -7

struct PdUDPPacket
{
  int64_t send_timestamp_;
  struct sockaddr_in peer_; 
};

extern int64_t pd_get_time();

extern void pd_bind_core(int64_t core_id);

extern int pd_intstr_size(int64_t x);

extern void pd_reverse_copy(char *dst, const char *src, const int len);

#endif

