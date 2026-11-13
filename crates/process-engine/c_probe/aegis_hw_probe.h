#ifndef AEGIS_HW_PROBE_H
#define AEGIS_HW_PROBE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint32_t threads;
    char     state;         /* 'R', 'S', 'D', 'Z', 'T', 'I' */
    uint64_t utime_ticks;
    uint64_t stime_ticks;
    uint64_t rss_kb;
    uint64_t start_time;
    char     name[64];
} AegisProcSample;

typedef struct {
    uint64_t total_cpu_ticks;
    uint64_t idle_cpu_ticks;
    uint64_t mem_total_kb;
    uint64_t mem_available_kb;
    uint32_t cpu_cores;
} AegisSysSample;

int aegis_read_sys_sample(AegisSysSample *out);
int aegis_read_proc_sample(uint32_t pid, AegisProcSample *out);

#ifdef __cplusplus
}
#endif

#endif
