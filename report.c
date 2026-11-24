#define _GNU_SOURCE
#include "report.h"
#include <errno.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wchar.h>

static FILE *out;
static const char *destination;
static char *temporary;
static int first;

static void die(const char *message)
{
    perror(message);
    exit(1);
}

static void cleanup(void)
{
    if (temporary)
        unlink(temporary);
}

void report_open(const char *path)
{
    struct stat st;
    if (lstat(path, &st) == 0) {
        errno = EEXIST;
        die(path);
    }
    if (errno != ENOENT)
        die(path);
    destination = path;
    if (asprintf(&temporary, "%s.XXXXXX", path) < 0)
        die("asprintf");
    int fd = mkstemp(temporary);
    if (fd < 0)
        die(path);
    atexit(cleanup);
    out = fdopen(fd, "w");
    if (!out)
        die("fdopen");
    setlocale(LC_CTYPE, "C.UTF-8");
    fputs("{\"version\":1,\"execs\":[", out);
    first = 1;
}

static void separator(void)
{
    fputs(first ? "\n" : ",\n", out);
    first = 0;
}

// Linux allows arbitrary bytes in argv. Replace invalid UTF-8 with U+FFFD.
static void string_value(const char *s)
{
    size_t left = strlen(s);
    fputc('"', out);
    while (left) {
        unsigned char c = (unsigned char)*s;
        size_t n = 1;
        if (c >= 128) {
            mbstate_t state = {0};
            size_t width = mbrlen(s, left, &state);
            if (width == (size_t)-1 || width == (size_t)-2)
                fputs("\\ufffd", out);
            else {
                n = width;
                fwrite(s, 1, n, out);
            }
        } else if (c < 32)
            fprintf(out, "\\u%04x", (unsigned)c);
        else {
            if (c == '"' || c == '\\')
                fputc('\\', out);
            fputc(c, out);
        }
        s += n;
        left -= n;
    }
    fputc('"', out);
}

static void arguments(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *args = fopen(path, "r");
    if (!args) {
        fputs("null", out);
        return;
    }
    char *arg = NULL;
    size_t capacity = 0;
    int count = 0;
    fputc('[', out);
    while (getdelim(&arg, &capacity, '\0', args) >= 0) {
        if (count++)
            fputc(',', out);
        string_value(arg);
    }
    if (ferror(args))
        die(path);
    fputc(']', out);
    free(arg);
    fclose(args);
}

void report_exec(unsigned id, pid_t pid, double at_ms, const char *image,
                 int have_ids, unsigned uid, unsigned euid)
{
    separator();
    fprintf(out, "{\"process\":%u,\"pid\":%d,\"at_ms\":%.3f,\"image\":", id, pid, at_ms);
    string_value(image);
    if (have_ids)
        fprintf(out, ",\"uid\":%u,\"euid\":%u", uid, euid);
    fputs(",\"argv\":", out);
    arguments(pid);
    fputc('}', out);
}

void report_begin_processes(void)
{
    fputs("],\"processes\":[", out);
    first = 1;
}

void report_process(unsigned id, pid_t pid, unsigned parent, const char *image,
                    double start_ms, double end_ms, int status)
{
    separator();
    fprintf(out, "{\"id\":%u,\"pid\":%d,\"parent\":", id, pid);
    if (parent)
        fprintf(out, "%u", parent);
    else
        fputs("null", out);
    fprintf(out, ",\"start_ms\":%.3f,\"end_ms\":%.3f,\"image\":", start_ms, end_ms);
    string_value(image);
    if (WIFEXITED(status))
        fprintf(out, ",\"exit_code\":%d}", WEXITSTATUS(status));
    else
        fprintf(out, ",\"signal\":%d}", WTERMSIG(status));
}

void report_finish(void)
{
    fputs("]}\n", out);
    if (ferror(out) || fclose(out) != 0)
        die(destination);
    if (link(temporary, destination) != 0)
        die(destination);
    cleanup();
    free(temporary);
    temporary = NULL;
}
