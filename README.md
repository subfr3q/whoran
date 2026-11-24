# whoran

WhoRan is a Linux process tracer written in C. Give it a command and it shows which process launched each child, how long each process ran, and how it exited. The tree goes to stderr, so you can still pipe the command's stdout to another program.

## Quick start

Build with a C compiler and make on Linux. The tracer needs access to /proc and permission to trace its own child processes.

```sh
make
./whoran -- sh -c 'sleep 1; echo done'
```

Example output (PIDs, executable names, and timings vary by system):

```text
done

Processes: 2, all exited successfully
dash (PID 4100)  │  1004 ms  │  trace root
└── sleep (PID 4101)  │  1001 ms  │  parent: dash (PID 4100)
```

Here `sh` resolves to `dash`. The shell starts sleep as a child. It then runs echo as a shell builtin, so only the shell and sleep appear in the tree. Each row shows its PID. A child row also names its parent at fork time and gives the parent PID, so the relationship survives copying the output without indentation. Each duration includes time spent waiting for children and time under tracing.

## Output language and detail

The summary and process tree use English by default. Select Russian with `--lang ru` or explicitly select English with `--lang en`. Both languages show the same processes, timings, exit codes, and signals. GCC stages include the detected source filename for cc1 when available.

```sh
./whoran --lang ru -- make -B
./whoran --verbose -- sh -c '/bin/true; exec /bin/echo OK'
```

Verbose mode adds fork and exec events with executable paths, PIDs, and available UID/EUID values. In the second example, the shell and echo share a PID because exec replaces the shell's executable.

## JSON reports

```sh
./whoran --json build.json -- make -B
python3 -m json.tool build.json
```

Use a new filename for each run. The report appears when tracing finishes and contains full command arguments. It is created with owner-only permissions. The language flag only affects the terminal report.

The execs array records observed exec events in order. argv preserves argument boundaries and empty strings, and is null if cmdline could not be opened. Each entry in processes has an internal id, system pid, parent ID, start and end times, and an exit code or signal. The process field on each exec event refers to the same internal ID. Times are monotonic milliseconds relative to the root process's first observed stop.

## Implementation and scope

The child calls PTRACE_TRACEME and stops before exec. The parent enables fork, vfork, and exec events, collects state changes with waitpid, and reads process details from /proc. The tracer targets single-threaded commands and descendants reported by fork and vfork events. Threads and interactive job control are outside its scope. Tracing may change setuid behavior, so credentials describe the traced execution.

Run `make test` with Python 3 installed and ptrace enabled to exercise the CLI, tree, and JSON output.
