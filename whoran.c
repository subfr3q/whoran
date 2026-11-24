#define _GNU_SOURCE
#include "report.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

typedef struct Process Process;
struct Process {
    unsigned id;
    pid_t pid;
    Process *parent, *first_child, *last_child, *sibling;
    bool started, finished;
    int status;
    struct timespec first_seen, last_seen;
    char image[PATH_MAX];
    char *source, *launcher;
    Process *next;
};

static Process *head, **tail = &head;

static bool recording, verbose, russian;
static unsigned next_id;

static const char *label(const char *en, const char *ru)
{
    return russian ? ru : en;
}

static double milliseconds(struct timespec from, struct timespec to)
{
    return (to.tv_sec - from.tv_sec) * 1000.0 + (to.tv_nsec - from.tv_nsec) / 1e6;
}

static void fail(const char *operation)
{
    perror(operation);
    exit(1);
}

// Parent and child fork notifications can arrive in either order.
static Process *process_for(pid_t pid)
{
    for (Process *p = head; p; p = p->next)
        if (p->pid == pid && !p->finished)
            return p;

    Process *p = calloc(1, sizeof(*p));
    if (!p)
        fail("calloc");
    if (clock_gettime(CLOCK_MONOTONIC, &p->first_seen) < 0)
        fail("clock_gettime");
    p->id = ++next_id;
    p->pid = pid;
    *tail = p;
    tail = &p->next;
    return p;
}

static const char *basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static char *compiler_input(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;
    char *arg = NULL, *source = NULL;
    size_t capacity = 0;
    while (getdelim(&arg, &capacity, '\0', f) > 0) {
        const char *ext = strrchr(arg, '.');
        if (arg[0] != '-' && ext && (!strcmp(ext, ".c") || !strcmp(ext, ".i"))) {
            source = strdup(arg);
            break;
        }
    }
    free(arg);
    fclose(f);
    return source;
}

static void snapshot(Process *p, const char *event)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", p->pid);
    ssize_t n = readlink(path, p->image, sizeof(p->image) - 1);
    if (n < 0)
        strcpy(p->image, "?");
    else
        p->image[n] = '\0';

    free(p->source);
    p->source = NULL;
    if (!strcmp(basename_of(p->image), "cc1"))
        p->source = compiler_input(p->pid);

    if (!verbose && !(recording && strcmp(event, "exec") == 0))
        return;
    snprintf(path, sizeof(path), "/proc/%d/status", p->pid);
    FILE *f = fopen(path, "r");
    unsigned uid = 0, euid = 0;
    bool have_ids = false;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "Uid: %u %u", &uid, &euid) == 2) {
                have_ids = true;
                break;
            }
        }
        fclose(f);
    }
    if (verbose) {
        fprintf(stderr, "[%s] pid=%d %s", event, p->pid, p->image);
        if (have_ids)
            fprintf(stderr, " uid=%u euid=%u", uid, euid);
        fputc('\n', stderr);
    }
    if (recording && strcmp(event, "exec") == 0) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
            fail("clock_gettime");
        report_exec(p->id, p->pid, milliseconds(head->first_seen, now),
                    p->image, have_ids, uid, euid);
    }
}

static void resume(pid_t pid, int sig)
{
    if (ptrace(PTRACE_CONT, pid, NULL, (long)sig) < 0 && errno != ESRCH)
        fail("PTRACE_CONT");
}

static void trace(Process *root)
{
    long options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
    if (ptrace(PTRACE_SETOPTIONS, root->pid, NULL, options) < 0)
        fail("PTRACE_SETOPTIONS");
    root->started = true;
    resume(root->pid, 0);

    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ECHILD)
                return;
            fail("waitpid");
        }
        Process *p = process_for(pid);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (clock_gettime(CLOCK_MONOTONIC, &p->last_seen) < 0)
                fail("clock_gettime");
            p->status = status;
            p->finished = true;
            continue;
        }
        if (!WIFSTOPPED(status))
            continue;

        unsigned event = (unsigned)status >> 16;
        int sig = WSTOPSIG(status);
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK) {
            unsigned long child;
            if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child) < 0)
                fail("PTRACE_GETEVENTMSG");
            Process *newborn = process_for((pid_t)child);
            newborn->parent = p;
            // The parent may exec a different program after this fork.
            newborn->launcher = strdup(p->image[0] ? basename_of(p->image) : "?");
            if (!newborn->launcher)
                fail("strdup");
            if (p->last_child)
                p->last_child->sibling = newborn;
            else
                p->first_child = newborn;
            p->last_child = newborn;
            if (newborn->started)
                resume(newborn->pid, 0);
        } else if (event == PTRACE_EVENT_EXEC) {
            snapshot(p, "exec");
        } else if (!p->started && sig == SIGSTOP) {
            p->started = true;
            snapshot(p, "fork");
            // Wait for both events before resuming a short-lived child.
            if (!p->parent)
                continue;
        } else {
            resume(pid, sig);
            continue;
        }
        resume(pid, 0);
    }
}

static void print_branch(const Process *p, bool tip)
{
    if (!p->parent)
        return;
    print_branch(p->parent, false);
    if (tip)
        fputs(p->sibling ? "├── " : "└── ", stderr);
    else
        fputs(p->sibling ? "│   " : "    ", stderr);
}

static void print_tree(const Process *p)
{
    print_branch(p, true);
    const char *name = basename_of(p->image);
    const char *suffix = strrchr(name, '-');
    if (!strcmp(name, "cc1") && p->source)
        fprintf(stderr, label("Compile %s", "Компиляция %s"), p->source);
    else if (!strcmp(name, "as") || (suffix && !strcmp(suffix, "-as")))
        fputs(label("Assembler (as)", "Ассемблер (as)"), stderr);
    else if (!strcmp(name, "collect2"))
        fputs(label("Link setup (collect2)", "Подготовка компоновки (collect2)"), stderr);
    else if (!strcmp(name, "ld.bfd") || (suffix && !strcmp(suffix, "-ld.bfd")))
        fputs(label("Link (ld.bfd)", "Компоновка (ld.bfd)"), stderr);
    else
        fputs(*name ? name : "?", stderr);

    fprintf(stderr, " (PID %d)", p->pid);
    fprintf(stderr, label("  │  %.0f ms", "  │  %.0f мс"), milliseconds(p->first_seen, p->last_seen));
    if (WIFSIGNALED(p->status))
        fprintf(stderr, label(", signal %d", ", сигнал %d"), WTERMSIG(p->status));
    else if (WEXITSTATUS(p->status))
        fprintf(stderr, label(", exit %d", ", код %d"), WEXITSTATUS(p->status));
    if (p->parent)
        fprintf(stderr, label("  │  parent: %s (PID %d)", "  │  родитель: %s (PID %d)"),
                p->launcher, p->parent->pid);
    else
        fputs(label("  │  trace root", "  │  начало трассировки"), stderr);
    fputc('\n', stderr);
    for (const Process *child = p->first_child; child; child = child->sibling)
        print_tree(child);
}

int main(int argc, char **argv)
{
    int separator = 1;
    const char *report_path = NULL;
    while (separator < argc) {
        if (strcmp(argv[separator], "--verbose") == 0)
            verbose = true;
        else if (strcmp(argv[separator], "--lang") == 0 && separator + 1 < argc) {
            const char *lang = argv[++separator];
            if (strcmp(lang, "en") && strcmp(lang, "ru")) {
                fputs("--lang requires en or ru\n", stderr);
                return 2;
            }
            russian = strcmp(lang, "ru") == 0;
        } else if (strcmp(argv[separator], "--json") == 0 && separator + 1 < argc && !report_path)
            report_path = argv[++separator];
        else
            break;
        separator++;
    }
    if (argc <= separator + 1 || strcmp(argv[separator], "--") != 0) {
        fprintf(stderr, "Usage: %s [--lang en|ru] [--verbose] [--json FILE] -- command [args...]\n", argv[0]);
        return 2;
    }
    char **command = argv + separator + 1;
    pid_t pid = fork();
    if (pid < 0)
        fail("fork");
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
            fail("PTRACE_TRACEME");
        raise(SIGSTOP); // Let the parent enable tracing before exec.
        execvp(command[0], command);
        int code = errno == ENOENT ? 127 : 126;
        perror(command[0]);
        _exit(code);
    }

    int status;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            fail("waitpid");
    if (!WIFSTOPPED(status))
        return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);

    if (report_path) {
        // Enable EXITKILL before opening the report can fail.
        if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (long)PTRACE_O_EXITKILL) < 0)
            fail("PTRACE_SETOPTIONS");
        report_open(report_path);
        recording = true;
    }
    Process *root = process_for(pid);
    trace(root);
    unsigned failed = 0;
    for (Process *p = head; p; p = p->next)
        if (!WIFEXITED(p->status) || WEXITSTATUS(p->status) != 0)
            failed++;
    fprintf(stderr, label("\nProcesses: %u", "\nВсего процессов: %u"), next_id);
    if (failed)
        fprintf(stderr, label(", signaled or exited nonzero: %u\n", ", с сигналом или ненулевым кодом: %u\n"), failed);
    else
        fputs(label(", all exited successfully\n", ", все завершились успешно\n"), stderr);
    print_tree(root);
    if (recording) {
        report_begin_processes();
        for (Process *p = head; p; p = p->next)
            report_process(p->id, p->pid, p->parent ? p->parent->id : 0,
                           p->image, milliseconds(root->first_seen, p->first_seen),
                           milliseconds(root->first_seen, p->last_seen), p->status);
        report_finish();
    }
    int result = WIFEXITED(root->status) ? WEXITSTATUS(root->status)
                                        : 128 + WTERMSIG(root->status);
    while (head) {
        Process *next = head->next;
        free(head->launcher);
        free(head->source);
        free(head);
        head = next;
    }
    return result;
}
