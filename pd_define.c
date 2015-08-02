#define _GNU_SOURCE
#include <sched.h>
#include <sys/time.h>
#include <pthread.h>
#include "pd_define.h"
#include "pd_log.h"

int64_t pd_get_time()
{
  struct timeval tp;
  gettimeofday(&tp, NULL);
  return (((int64_t) tp.tv_sec) * 1000000 + (int64_t) tp.tv_usec);
}

void pd_bind_core(int64_t bind_core_id)
{
  if (-1 == bind_core_id)
  {
    // need not bind
  }
  else
  {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(bind_core_id, &cpuset);
    int tmp_ret = 0;
    if (0 != (tmp_ret = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)))
    {
      PD_LOG(WARN, "bind_core fail, bind_core_id=%ld ret=%d", bind_core_id, tmp_ret);
    }
    else
    {
      PD_LOG(INFO, "bind_core succ, bind_core_id=%ld", bind_core_id);
    }
  }
}

int pd_intstr_size(int64_t x)
{
  if(x >= 100000)
  {
    if(x >= 10000000)
    {
      if(x > 1000000000)
      {
        char BUF[PD_MAX_INTSTR_SIZE];
        return sprintf(BUF, "%ld", x);
      }
      if(x == 1000000000)
      {
        return 10;
      }
      if(x >= 100000000)
      {
        return 9;
      }
      return 8;
    }
    if(x >= 1000000)
    {
      return 7;
    }
    return 6;
  }
  else
  {
    if(x >= 1000)
    {
      if(x >= 10000)
      {
        return 5;
      }
      return 4;
    }
    else
    {
      if(x >= 100)
      {
        return 3;
      }
      if(x >= 10)
      {
        return 2;
      }
      return 1;
    }
  }
}

void pd_reverse_copy(char *dst, const char *src, const int len)
{
  int64_t i64c = len / 8;
  int64_t i32c = (len % 8) / 4;
  int64_t i8c = len % 4;

  int64_t i = 0;
  for (i = 0; i < i64c; i++)
  {
    int64_t *i64src = (int64_t*)(src + len - sizeof(int64_t) * (i + 1));
    int64_t *i64dst = (int64_t*)(dst + sizeof(int64_t) * i);
    *i64dst = __builtin_bswap64(*i64src);
  }
  if (0 < i32c)
  {
    int64_t *i32src = (int64_t*)(src + i8c);
    int64_t *i32dst = (int64_t*)(dst + len - i8c - sizeof(int32_t));
    *i32dst = __builtin_bswap32(*i32src);
  }
  for (i = 0; i < i8c; i++)
  {
    dst[len - i8c + i] = src[i8c - i - 1];
  }
}

