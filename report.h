#ifndef REPORT_H
#define REPORT_H
#include <stdio.h>
#include <sys/types.h>

// Timestamps are relative to the first stop of the root process.
void report_open(const char *path);
void report_exec(unsigned id, pid_t pid, double at_ms, const char *image,
                 int have_ids, unsigned uid, unsigned euid);
void report_begin_processes(void);
void report_process(unsigned id, pid_t pid, unsigned parent, const char *image,
                    double start_ms, double end_ms, int status);
void report_finish(void);
#endif
