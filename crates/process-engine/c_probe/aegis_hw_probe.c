#define _GNU_SOURCE
#include "aegis_hw_probe.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_small_file(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return (int)n;
}

int aegis_read_sys_sample(AegisSysSample *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    out->cpu_cores = (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
    if (out->cpu_cores == 0) out->cpu_cores = 1;

    char buf[4096];
    if (read_small_file("/proc/stat", buf, sizeof(buf)) > 0) {
        uint64_t user = 0, nice = 0, sys = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0;
        if (sscanf(buf, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                   (unsigned long long *)&user,
                   (unsigned long long *)&nice,
                   (unsigned long long *)&sys,
                   (unsigned long long *)&idle,
                   (unsigned long long *)&iowait,
                   (unsigned long long *)&irq,
                   (unsigned long long *)&softirq,
                   (unsigned long long *)&steal) >= 4) {
            out->idle_cpu_ticks  = idle + iowait;
            out->total_cpu_ticks = user + nice + sys + idle + iowait + irq + softirq + steal;
        }
    }

    if (read_small_file("/proc/meminfo", buf, sizeof(buf)) > 0) {
        char *line = buf;
        while (line && *line) {
            char *next = strchr(line, '\n');
            if (next) *next++ = '\0';
            uint64_t val = 0;
            if (sscanf(line, "MemTotal: %llu kB", (unsigned long long *)&val) == 1) {
                out->mem_total_kb = val;
            } else if (sscanf(line, "MemAvailable: %llu kB", (unsigned long long *)&val) == 1) {
                out->mem_available_kb = val;
            }
            line = next;
        }
    }
    return 0;
}

int aegis_read_proc_sample(uint32_t pid, AegisProcSample *out) {
    if (!out || pid == 0) return -1;
    memset(out, 0, sizeof(*out));
    out->pid   = pid;
    out->state = 'S';
    out->threads = 1;

    char path[128];
    char buf[4096];

    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    if (read_small_file(path, buf, sizeof(buf)) < 0) return -1;

    char *line = buf;
    while (line && *line) {
        char *next = strchr(line, '\n');
        if (next) *next++ = '\0';
        if (strncmp(line, "Name:\t", 6) == 0) {
            snprintf(out->name, sizeof(out->name), "%s", line + 6);
        } else if (strncmp(line, "State:\t", 7) == 0) {
            out->state = line[7];
        } else if (strncmp(line, "PPid:\t", 6) == 0) {
            out->ppid = (uint32_t)strtoul(line + 6, NULL, 10);
        } else if (strncmp(line, "Uid:\t", 5) == 0) {
            out->uid = (uint32_t)strtoul(line + 5, NULL, 10);
        } else if (strncmp(line, "Gid:\t", 5) == 0) {
            out->gid = (uint32_t)strtoul(line + 5, NULL, 10);
        } else if (strncmp(line, "VmRSS:\t", 7) == 0) {
            out->rss_kb = (uint64_t)strtoull(line + 7, NULL, 10);
        } else if (strncmp(line, "Threads:\t", 9) == 0) {
            out->threads = (uint32_t)strtoul(line + 9, NULL, 10);
        }
        line = next;
    }

    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    if (read_small_file(path, buf, sizeof(buf)) > 0) {
        char *rparen = strrchr(buf, ')');
        if (rparen && rparen[1] == ' ') {
            char *p = rparen + 2;
            char *save = NULL;
            char *tok = strtok_r(p, " ", &save);
            int idx = 0;
            while (tok) {
                /* idx 0: state, 11: utime, 12: stime, 19: starttime */
                if (idx == 0) out->state = tok[0];
                else if (idx == 11) out->utime_ticks = strtoull(tok, NULL, 10);
                else if (idx == 12) out->stime_ticks = strtoull(tok, NULL, 10);
                else if (idx == 19) { out->start_time = strtoull(tok, NULL, 10); break; }
                tok = strtok_r(NULL, " ", &save);
                idx++;
            }
        }
    }
    return 0;
}
