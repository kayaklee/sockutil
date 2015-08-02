#ifndef PD_LOG_H_
#define PD_LOG_H_

#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdint.h>
#include <execinfo.h>
#include "pd_define.h"

#define FATAL 0
#define WARN  1
#define INFO  2
#define TRACE 3
#define DEBUG 4

#define PD_FATAL    "FATAL"
#define PD_WARN     "WARN"
#define PD_INFO     "INFO"
#define PD_TRACE    "TRACE"
#define PD_DEBUG    "DEBUG"

#define PD_LOG(_loglevel_, _fmt_, args...) \
  do \
  { \
    if (pd_log_get_glevel() >= _loglevel_) \
    { \
      struct timeval log_tm;\
      struct tm date_tm; \
      gettimeofday(&log_tm, NULL); \
      localtime_r(&log_tm.tv_sec, &date_tm); \
      fprintf(stderr, \
          "[%s] [%04d-%02d-%02d %02d:%02d:%02d:%ld] %d [%s][%d][%s] " _fmt_ "\n", \
          PD_##_loglevel_, \
          1900 + date_tm.tm_year, date_tm.tm_mon + 1, date_tm.tm_mday, date_tm.tm_hour, date_tm.tm_min, date_tm.tm_sec, log_tm.tv_usec, \
          (int)GETTID(), __FILE__, __LINE__, __FUNCTION__, \
          ##args); \
    } \
  } while (0) \

#define PD_BACKTRACE(_fmt_, args...) \
  do \
  { \
    PD_LOG(INFO, _fmt_ " BackTrace Start: %s", ##args, pd_log_print_bt()); \
  } while (0)

extern const char* pd_log_print_array(char* buf, int64_t len, int64_t* array, int size);

extern const char* pd_log_print_bt();

extern void pd_log_set_glevel(const int level);

extern int pd_log_get_glevel();

#endif

