#!/usr/bin/env python3
"""A plugin's ARM program run against a stand-in broker under qemu-arm, every system call it makes judged by the
sandbox's own table (hassmic's docs/plugins.md 5.8, "The filter on the PC"): the index's smoke test of a community
version not published yet (index.py smoke, a pull request's job without secrets), on the program of the package its
author's CI released; nothing is built here (tools/sandbox.py).

    harness.py PROGRAM MANIFEST [--qemu QEMU_ARM] [--seconds N]

Why not the kernel's filter: qemu-arm takes no guest seccomp filter (a guest's prctl(PR_SET_SECCOMP) gets EINVAL),
and a host filter around qemu would judge qemu's own x86-64 calls, not the plugin's ARM ones.  So the program runs
under `qemu-arm -strace` and each guest call, number and arguments, is judged by tools/filter.def (hassmic's
sdk/filter.def, the table the launcher's BPF is generated from) through tools/mkfilter.py's judge() (hassmic's
tools/mkfilter.py): the table, not the kernel's filter.  The first call the table refuses ends the run and the
plugin is refused.  A call the table answers ENOSYS (those above 3.18's last, 386: statx, the time64 calls) is not
refused here: on an Echo the runtime gets ENOSYS and falls back (musl and Go do), under qemu it goes through; each is
named in the report.

A smoke test, not a wall.  qemu writes a call into its log before the call runs and the harness reads the log after:
what a refused call did, it did (inside the sandbox sandbox.sandbox makes around qemu).  qemu-user runs the
program in its own process, one table of descriptors for both, qemu's log among them: so a call on any descriptor
the program was neither given (0 to 3) nor made is refused (Trace), and the log is read a line at a time, a line
that is not one qemu writes refusing the run (a program that wrote into the log).  What it cannot show: a program
can tell qemu (uname says the PC's kernel; timing) and behave while it runs; it can wait out the run's seconds;
ARM's private calls (0xf0000 to 0xf07ff: cacheflush, set_tls) are qemu's own and never logged; how a runtime takes
a refusal; where qemu's emulation differs from a 3.18 kernel.  The boundary is the Echo's: the launcher's seccomp
filter, made from the same table, on every call (hassmic's docs/plugins.md 2.4; scripts/plugin-probe.sh runs it on
an Echo).  The run is bounded (sandbox.LIMITS["harness"]: address space, its log's and stderr's size, CPU,
processes; a process group of its own, ended whole), and what it printed is read from its end only.

What the stand-in broker does, from hassmic's sdk/PROTOCOL.md "The start": HELLO (every scope its client speaks; one
the manifest's "requires" names at a higher version or not at all, or a scope named twice: REFUSED SCOPES) -> WELCOME
(the manifest's capabilities granted, and exactly its "requires" as what is spoken from here on) -> FILES (empty) for each file list -> CONFIG (each row's default,
"" where it has none: no server entered) -> READY within 10 s (the Echo gives 5 s from WELCOME; qemu is slower).
Then PING every second for SECONDS, each answered within 5 s; requests answered as an Echo with nothing set up
would (storage kept in memory, a CONNECT "UNSET", the rest "FAILED"); then STOP, and the program has 2 s to end by
itself (the Echo's 2 s before SIGTERM).  Ending before STOP, a signal, a message that is no message of the protocol,
over 1000 messages a second: refused.  The ARM program only: the PC's test plugins are hassmic's own tests'."""
import json, os, re, select, shutil, signal, socket, stat, struct, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sandbox, mkfilter                      # mkfilter: hassmic's tools/mkfilter.py (tools/sync.sh)

TABLE = mkfilter.load(os.path.join(HERE, "filter.def"))
# The scopes this tool knows (hassmic's sdk/messages.def: core and one per capability, in the manifest's names)
SCOPES_KNOWN = ("core", "storage", "files", "state", "log.read", "log.read.full", "net.server", "net.lan", "net.internet", "net.udp",
                "net.discover", "audio.music", "audio.volume", "call", "wake", "request.audio", "request.text", "ha.entities",
                "ha.actions", "button")
HELLO, WELCOME, REFUSED, CONFIG, READY, PING, PONG, STOP, OK, ERR = 1, 2, 3, 4, 5, 6, 7, 8, 10, 11
FILES, STORE_GET, STORE_VALUE, STORE_PUT, STORE_DEL, CONNECT = 20, 40, 41, 42, 43, 60
# what the plugin may send: the protocol's types from the plugin (messages.def: > or =); anything else is no message
FROM_PLUGIN = {1, 5, 7, 10, 11, 21, 23, 24, 30, 32, 33, 36, 40, 42, 43, 50, 60, 61, 63, 64, 65, 66, 70, 71, 72, 75, 90, 91,
               100, 103, 104, 105, 106}
ERR_UNKNOWN, ERR_BAD, ERR_NOT_FOUND, ERR_FAILED, ERR_UNSET = 1, 3, 6, 7, 8
REFUSED_SCOPES = 1                              # (messages.def's REFUSED why)
SCOPE_NAME, SCOPES_MOST = 24, 255               # a HELLO's and a WELCOME's scope names (bytes) and their count: every
                                                # scope there will ever be (hassmic's PM_SCOPES_MAX: the greeting never grows)
MAX_PACKET = 32768

# ARM EABI numbers of the calls above 386 that a runtime may try first (asm/unistd-common.h): the table answers each
# ENOSYS ("above 386 ENOSYS"), and a name qemu prints that is neither here nor in filter.def is one of 3.18's own
# calls the table does not allow (EPERM)
NEWER = {"execveat": 387, "userfaultfd": 388, "membarrier": 389, "mlock2": 390, "copy_file_range": 391, "preadv2": 392,
         "pwritev2": 393, "pkey_mprotect": 394, "pkey_alloc": 395, "pkey_free": 396, "statx": 397, "rseq": 398,
         "io_pgetevents": 399, "migrate_pages": 400, "kexec_file_load": 401, "clock_gettime64": 403,
         "clock_settime64": 404, "clock_adjtime64": 405, "clock_getres_time64": 406, "clock_nanosleep_time64": 407,
         "timer_gettime64": 408, "timer_settime64": 409, "timerfd_gettime64": 410, "timerfd_settime64": 411,
         "utimensat_time64": 412, "pselect6_time64": 413, "ppoll_time64": 414, "io_pgetevents_time64": 416,
         "recvmmsg_time64": 417, "mq_timedsend_time64": 418, "mq_timedreceive_time64": 419, "semtimedop_time64": 420,
         "rt_sigtimedwait_time64": 421, "futex_time64": 422, "sched_rr_get_interval_time64": 423,
         "pidfd_send_signal": 424, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
         "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433,
         "pidfd_open": 434, "clone3": 435, "close_range": 436, "openat2": 437, "pidfd_getfd": 438, "faccessat2": 439,
         "process_madvise": 440, "epoll_pwait2": 441, "mount_setattr": 442, "quotactl_fd": 443,
         "landlock_create_ruleset": 444, "landlock_add_rule": 445, "landlock_restrict_self": 446,
         "process_mrelease": 448, "futex_waitv": 449, "set_mempolicy_home_node": 450, "cachestat": 451,
         "fchmodat2": 452}
# The names qemu writes for an argument's bits, with their values on ARM (the kernel's uapi headers).  An argument
# the table looks at that is written with a name not here is not read: the call counts as refused, said so.  Every
# value the table allows is named here, so that rule refuses nothing the filter would let through
SYMBOLS = {
    "NULL": 0,
    "PROT_NONE": 0, "PROT_READ": 1, "PROT_WRITE": 2, "PROT_EXEC": 4, "PROT_SEM": 8, "PROT_GROWSDOWN": 0x01000000,
    "PROT_GROWSUP": 0x02000000,
    "MAP_SHARED": 1, "MAP_PRIVATE": 2, "MAP_SHARED_VALIDATE": 3, "MAP_FIXED": 0x10, "MAP_ANONYMOUS": 0x20,
    "MAP_GROWSDOWN": 0x100, "MAP_DENYWRITE": 0x800, "MAP_EXECUTABLE": 0x1000, "MAP_LOCKED": 0x2000,
    "MAP_NORESERVE": 0x4000, "MAP_POPULATE": 0x8000, "MAP_NONBLOCK": 0x10000, "MAP_STACK": 0x20000,
    "MAP_HUGETLB": 0x40000, "MAP_SYNC": 0x80000, "MAP_FIXED_NOREPLACE": 0x100000, "MAP_UNINITIALIZED": 0x4000000,
    "MADV_NORMAL": 0, "MADV_RANDOM": 1, "MADV_SEQUENTIAL": 2, "MADV_WILLNEED": 3, "MADV_DONTNEED": 4, "MADV_FREE": 8,
    "MADV_REMOVE": 9, "MADV_DONTFORK": 10, "MADV_DOFORK": 11, "MADV_MERGEABLE": 12, "MADV_UNMERGEABLE": 13,
    "MADV_HUGEPAGE": 14, "MADV_NOHUGEPAGE": 15, "MADV_DONTDUMP": 16, "MADV_DODUMP": 17,
    "CLONE_VM": 0x100, "CLONE_FS": 0x200, "CLONE_FILES": 0x400, "CLONE_SIGHAND": 0x800, "CLONE_PIDFD": 0x1000,
    "CLONE_PTRACE": 0x2000, "CLONE_VFORK": 0x4000, "CLONE_PARENT": 0x8000, "CLONE_THREAD": 0x10000,
    "CLONE_NEWNS": 0x20000, "CLONE_SYSVSEM": 0x40000, "CLONE_SETTLS": 0x80000, "CLONE_PARENT_SETTID": 0x100000,
    "CLONE_CHILD_CLEARTID": 0x200000, "CLONE_DETACHED": 0x400000, "CLONE_UNTRACED": 0x800000,
    "CLONE_CHILD_SETTID": 0x1000000, "CLONE_NEWCGROUP": 0x2000000, "CLONE_NEWUTS": 0x4000000,
    "CLONE_NEWIPC": 0x8000000, "CLONE_NEWUSER": 0x10000000, "CLONE_NEWPID": 0x20000000, "CLONE_NEWNET": 0x40000000,
    "CLONE_IO": 0x80000000,
    "FUTEX_WAIT": 0, "FUTEX_WAKE": 1, "FUTEX_FD": 2, "FUTEX_REQUEUE": 3, "FUTEX_CMP_REQUEUE": 4, "FUTEX_WAKE_OP": 5,
    "FUTEX_LOCK_PI": 6, "FUTEX_UNLOCK_PI": 7, "FUTEX_TRYLOCK_PI": 8, "FUTEX_WAIT_BITSET": 9, "FUTEX_WAKE_BITSET": 10,
    "FUTEX_WAIT_REQUEUE_PI": 11, "FUTEX_CMP_REQUEUE_PI": 12, "FUTEX_LOCK_PI2": 13, "FUTEX_PRIVATE_FLAG": 128,
    "FUTEX_CLOCK_REALTIME": 256,
    "F_DUPFD": 0, "F_GETFD": 1, "F_SETFD": 2, "F_GETFL": 3, "F_SETFL": 4, "F_GETLK": 5, "F_SETLK": 6, "F_SETLKW": 7,
    "F_SETOWN": 8, "F_GETOWN": 9, "F_SETSIG": 10, "F_GETSIG": 11, "F_GETLK64": 12, "F_SETLK64": 13,
    "F_SETLKW64": 14, "F_SETOWN_EX": 15, "F_GETOWN_EX": 16, "F_OFD_GETLK": 36, "F_OFD_SETLK": 37,
    "F_OFD_SETLKW": 38, "F_SETLEASE": 1024, "F_GETLEASE": 1025, "F_NOTIFY": 1026, "F_CANCELLK": 1029,
    "F_DUPFD_CLOEXEC": 1030, "F_SETPIPE_SZ": 1031, "F_GETPIPE_SZ": 1032, "F_ADD_SEALS": 1033, "F_GET_SEALS": 1034,
    "FIONREAD": 0x541B, "FIONBIO": 0x5421, "FIOCLEX": 0x5451, "FIONCLEX": 0x5450, "FIOASYNC": 0x5452,
    "TCGETS": 0x5401, "TCSETS": 0x5402, "TIOCGWINSZ": 0x5413, "TIOCSWINSZ": 0x5414, "TIOCGPGRP": 0x540F,
    "TIOCSPGRP": 0x5410, "TIOCOUTQ": 0x5411, "TIOCSTI": 0x5412, "TIOCSCTTY": 0x540E,
    # a send's and a receive's flags: qemu 11 writes them by name (7.2 and 8.2 wrote the number), and the table looks
    # at send's and sendto's (MSG_DONTWAIT|MSG_NOSIGNAL)
    "MSG_OOB": 1, "MSG_PEEK": 2, "MSG_DONTROUTE": 4, "MSG_CTRUNC": 8, "MSG_PROXY": 0x10, "MSG_TRUNC": 0x20,
    "MSG_DONTWAIT": 0x40, "MSG_EOR": 0x80, "MSG_WAITALL": 0x100, "MSG_FIN": 0x200, "MSG_SYN": 0x400, "MSG_CONFIRM": 0x800,
    "MSG_RST": 0x1000, "MSG_ERRQUEUE": 0x2000, "MSG_NOSIGNAL": 0x4000, "MSG_MORE": 0x8000, "MSG_WAITFORONE": 0x10000,
    "MSG_BATCH": 0x40000, "MSG_ZEROCOPY": 0x4000000, "MSG_FASTOPEN": 0x20000000, "MSG_CMSG_CLOEXEC": 0x40000000,
}
NUMBER = re.compile(r"-?(?:0x[0-9a-fA-F]+|[0-9]+)")
# qemu's -strace log, as qemu 7.2 and 8.2 write it: each piece whole and flushed at once (qemu_log_trylock), a call
# as "<pid> <name>(<arguments>)" before it runs, its result as " = <...>\n" after it (another thread's call can come
# between the two), "<pid> Unknown syscall <n>\n", a signal as "--- ... ---\n".  Read a line at a time
LINE_MAX = 8192                                 # a line longer than this (qemu's longest is a path, 4096) is no log
RECORD = re.compile(r"([0-9]{1,10}) ([a-z_][a-z0-9_]{0,47})\(")
UNKNOWN = re.compile(r"([0-9]{1,10}) Unknown syscall ([0-9]{1,10})")
# The descriptors a plugin is given (hassmic's launcher): 0 /dev/null, 1 and 2 its log, 3 its control socket
GIVEN = (0, 1, 2, 3)
# Which arguments of a call are descriptors (a directory's, of the *at calls: AT_FDCWD is none).  The table's own
# calls and those it answers ENOSYS, which under qemu go through (on an Echo they never run)
FD_ARGS = {n: (0,) for n in (
    "read", "write", "readv", "writev", "close", "lseek", "_llseek", "fstat64", "fstat", "dup", "fcntl", "fcntl64", "ioctl",
    "epoll_wait", "epoll_pwait", "recv", "recvfrom", "recvmsg", "send", "sendto", "shutdown", "getsockname", "getpeername",
    "getsockopt", "setsockopt", "dup3", "dup2", "preadv2", "pwritev2", "epoll_pwait2", "recvmmsg_time64", "io_uring_enter",
    "io_uring_register", "mq_timedsend_time64", "mq_timedreceive_time64", "timerfd_gettime64", "timerfd_settime64",
    "pidfd_send_signal", "pidfd_getfd", "process_madvise", "process_mrelease", "landlock_add_rule", "landlock_restrict_self",
    "quotactl_fd", "cachestat", "fsconfig", "fsmount", "execveat", "statx", "utimensat_time64", "openat2", "faccessat2",
    "fchmodat2", "open_tree", "fspick", "mount_setattr", "readlinkat", "newfstatat", "openat", "fstatat64")}
FD_ARGS.update({"epoll_ctl": (0, 2), "copy_file_range": (0, 2), "move_mount": (0, 2)})
# calls that make one descriptor more, the lowest free one (pipe2: two, which qemu does not write down)
NEW_FD = {"dup", "eventfd2", "epoll_create1", "pidfd_open", "openat2", "userfaultfd", "open", "openat", "socket",
          "memfd_create", "timerfd_create", "signalfd4", "inotify_init1", "fanotify_init", "accept4", "accept",
          "fsopen", "fsmount", "open_tree", "fspick", "landlock_create_ruleset", "pidfd_getfd", "perf_event_open"}


class Unreadable(Exception):
    pass


def value(token):
    """an argument as qemu wrote it: a number, NULL, or names of bits joined by |.  None: not one this reads"""
    token = token.strip()
    if NUMBER.fullmatch(token):
        return int(token, 0) & 0xFFFFFFFF
    # (names, and the bits qemu has no name for as numbers: "MAP_PRIVATE|MAP_ANONYMOUS|0x20000")
    if token and all(n in SYMBOLS or NUMBER.fullmatch(n) for n in token.split("|")):
        v = 0
        for n in token.split("|"):
            v |= SYMBOLS[n] if n in SYMBOLS else int(n, 0) & 0xFFFFFFFF
        return v
    return None


def split_args(text):
    """qemu's argument list split at its top-level commas (a quoted text or a bracket keeps its own)"""
    out, depth, quote, cur, i = [], 0, False, "", 0
    while i < len(text):
        c = text[i]
        if quote:
            cur += c
            if c == "\\" and i + 1 < len(text):
                cur += text[i + 1]; i += 1
            elif c == '"':
                quote = False
        elif c == '"':
            quote = True; cur += c
        elif c in "([{":
            depth += 1; cur += c
        elif c in ")]}":
            depth -= 1; cur += c
        elif c == "," and depth == 0:
            out.append(cur); cur = ""
        else:
            cur += c
        i += 1
    if cur or out:
        out.append(cur)
    # (clone's "child_stack=0x..." and its like: the value after the name)
    return [a.split("=", 1)[1] if re.match(r"[a-z_]+=", a) else a for a in out]


def closing(text, at):
    """the index of the ")" that closes the argument list opening before AT, None when it does not close in TEXT"""
    depth, quote, i = 1, False, at
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == '"':
                quote = False
        elif c == '"':
            quote = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if not depth:
                return i
        i += 1
    return None


def number_of(name):
    """the call's ARM number: filter.def's, else NEWER's, else -1 (one of the old calls the table does not name)"""
    nr = TABLE["nr"].get(name, (None, None))[0]
    return nr if nr is not None else NEWER.get(name, -1)


def verdict(name, nr, args, pid):
    """('allow' | 'enosys' | 'refused', why) for one call as the table judges it"""
    entry = [c for c in mkfilter.calls(TABLE, "arm") if c[0] == nr]
    needed = sorted({a for _, _, _, alts in entry for cs in alts for a, _, _ in cs})
    vals = [value(a) for a in args] + [None] * 6
    for a in needed:
        if vals[a] is None:
            return "refused", f"its argument {a + 1} ({args[a] if a < len(args) else 'none'}) is none the harness reads, and the table looks at it"
    got = mkfilter.judge(TABLE, "arm", nr, [v if v is not None else 0 for v in vals[:6]], {"PID": pid})
    if got == "allow":
        return "allow", ""
    if got == mkfilter.CONST["ENOSYS"]:
        return "enosys", "answered ENOSYS on an Echo (newer than its kernel): the runtime falls back"
    return "refused", "the table refuses it" + (" (EPERM)" if got == mkfilter.CONST["EPERM"] else f" (errno {got})")


def printable(text):
    """TEXT with control characters as ? (it goes into a CI log)"""
    return "".join(c if " " <= c < "\x7f" or c > "\x9f" else "?" for c in text)


def parse_line(line):
    """the calls of one line of the log: [(pid, name, arguments' text, result's text or None)], ("unknown", pid, n)
    for "Unknown syscall"; Unreadable for a line that is not one qemu writes"""
    out, i = [], 0
    if line.startswith(" = "):                          # a result alone: its call's line was another's
        return out
    while i < len(line):
        if line.startswith(("--- ", "+++ "), i) and line.endswith((" ---", " +++")):
            return out                                  # a signal qemu says
        m = RECORD.match(line, i)
        if not m:
            u = UNKNOWN.fullmatch(line, i)
            if u:
                out.append(("unknown", int(u.group(1)), int(u.group(2))))
                return out
            raise Unreadable(f"a line of the log that is no call: {printable(line[i:i + 120])!r}")
        end = closing(line, m.end())
        if end is None:
            raise Unreadable(f"a call whose argument list does not close on its line: {printable(line[i:i + 120])!r}")
        args = line[m.end():end]
        i = end + 1
        if line.startswith(" = ", i):                   # its result (or, with threads, another's): the rest of the line
            out.append((int(m.group(1)), m.group(2), args, line[i + 3:]))
            return out
        out.append((int(m.group(1)), m.group(2), args, None))
    return out


class Trace:
    """qemu's -strace log read as it grows, a line at a time, each call once its line is whole; and the descriptors
    the program holds: those it was given (GIVEN) and those it made, counted call by call.  QEMU: qemu's own
    descriptors (its log's among them), which the program shares a table with: a call on any descriptor that is not
    the program's is named (`foreign`), and the harness refuses it.  qemu writes no result of pipe2, and with threads
    a result cannot be told to its call: a new descriptor is then the lowest one free, as the kernel gives it"""
    def __init__(self, qemu=()):
        self.buf, self.fds, self.qemu, self.threads, self.broken = "", set(GIVEN), set(qemu), False, ""

    def feed(self, more):
        """the calls of the lines MORE completes: [(pid, name, nr, args, shown, foreign)]; from a line that does not
        read on, none, and self.broken says why"""
        self.buf += more
        lines = self.buf.split("\n")
        self.buf = lines.pop()
        calls = self._lines(lines)
        if len(self.buf) > LINE_MAX and not self.broken:
            self.broken = f"a line of the log longer than {LINE_MAX} characters"
        return calls

    def finish(self):
        """the calls of the last line, which has no end (the program was ended inside a call)"""
        rest, self.buf = self.buf, ""
        return self._lines([rest] if rest else [])

    def _lines(self, lines):
        """the calls of LINES up to the first that does not read; that one's why in self.broken (the calls before it
        are judged first: a write into the log is named by its own line, which comes before what it wrote)"""
        calls = []
        for line in lines:
            if self.broken:
                break
            try:
                if len(line) > LINE_MAX:
                    raise Unreadable(f"a line of the log longer than {LINE_MAX} characters")
                got = parse_line(line)
            except Unreadable as x:
                self.broken = str(x)
                break
            for c in got:
                if c[0] == "unknown":
                    calls.append((c[1], f"syscall {c[2]}", c[2], [], printable(f"Unknown syscall {c[2]}"), ""))
                    continue
                pid, name, args, result = c
                a = split_args(args) if args else []
                calls.append((pid, name, number_of(name), a, printable(f"{name}({args[:160]})"), self.descriptors(name, a, result)))
        return calls

    def free(self, at_least=0):
        n = at_least
        while n in self.fds or n in self.qemu:
            n += 1
        return n

    def descriptors(self, name, a, result):
        """'' or why the call is on a descriptor that is not the program's; the program's descriptors after it"""
        def fd(k):
            v = value(a[k]) if k < len(a) else None
            if v is None:
                return None if k < len(a) and a[k].strip() == "AT_FDCWD" else -2
            return v - (1 << 32) if v >= 1 << 31 else v
        for k in FD_ARGS.get(name, ()):
            v = fd(k)
            if v == -2:
                return f"its descriptor argument {k + 1} is none the harness reads"
            if v is not None and v >= 0 and v not in self.fds:
                return f"descriptor {v} is not the plugin's (" + ("qemu's own" if v in self.qemu else "neither given it nor made by it") + ")"
        if name in ("clone", "clone3"):
            self.threads = True                         # (from here on a result may be another thread's)
        ok, got = True, None
        if result is not None and not self.threads:
            r = re.match(r"(-?[0-9]+|0x[0-9a-f]+)", result)
            got = int(r.group(1), 0) if r else None
            ok = got is not None and got >= 0
        if not ok:
            return ""                                   # (it failed: nothing made)
        if name == "close":
            self.fds.discard(fd(0))
        elif name == "close_range":
            lo, hi = value(a[0]) if a else None, value(a[1]) if len(a) > 1 else None
            if lo is None or hi is None:
                return "close_range's range is none the harness reads"
            if any(lo <= q <= hi for q in self.qemu):
                return "close_range over qemu's own descriptors"
            self.fds = {f for f in self.fds if not lo <= f <= hi}
        elif name in ("dup3", "dup2"):
            v = fd(1)
            if v is None or v < 0:
                return "its new descriptor is none the harness reads"
            if v in self.qemu:
                return f"descriptor {v} is not the plugin's (qemu's own)"
            self.fds.add(v)
        elif name in ("fcntl", "fcntl64") and len(a) > 1 and value(a[1]) in (SYMBOLS["F_DUPFD"], SYMBOLS["F_DUPFD_CLOEXEC"]):
            least = value(a[2]) if len(a) > 2 else 0
            self.fds.add(got if got is not None and got not in self.qemu else self.free(least or 0))
        elif name == "pipe2":
            r = self.free()
            self.fds.add(r)
            self.fds.add(self.free())
        elif name in NEW_FD:
            self.fds.add(got if got is not None and got not in self.qemu else self.free())
        return ""


def s(text):
    b = text if isinstance(text, bytes) else text.encode()
    return struct.pack("<H", len(b)) + b


def hello_scopes(d):
    """the scopes a HELLO packet D offers, {name: version}, the names this tool does not know among them (a later SDK's;
    none is spoken); None where one is named twice.  ValueError for a packet that is not exactly HELLO's layout
    (sdk/vectors/HELLO.vec: u32 sdk, then a list of at most 255 {text of at most 24 bytes, no NUL; u16 version}, and
    nothing after it).  Twice counts among the scopes this tool knows, as hassmic's broker counts it"""
    at = 12
    n, = struct.unpack_from("<H", d, at)
    at += 2
    if n > SCOPES_MOST:
        raise ValueError(f"{n} scopes, more than {SCOPES_MOST}")
    got, twice = {}, False
    for _ in range(n):
        name, at = rs(d, at)
        if len(name) > SCOPE_NAME or b"\0" in name:
            raise ValueError("a scope's name of more than 24 bytes, or with a NUL")
        v, = struct.unpack_from("<H", d, at)
        at += 2
        k = name.decode("utf-8", "replace")
        twice |= k in got and k in SCOPES_KNOWN
        got[k] = v
    if at != len(d):
        raise ValueError(f"{len(d) - at} bytes after its last field")
    return None if twice else got


def packet(kind, mid, body=b""):
    return struct.pack("<HHI", kind, 0, mid) + body


def rs(b, at):
    n, = struct.unpack_from("<H", b, at)
    if at + 2 + n > len(b):
        raise ValueError("a text past the packet's end")
    return b[at + 2:at + 2 + n], at + 2 + n


def config_value(row):
    """a row's value as hassmic sends it before the owner set any (plugin_store.c config_read: the default, else "")"""
    if "default" not in row:
        return ""
    d = row["default"]
    if isinstance(d, bool):
        return "1" if d else "0"
    return str(d)


class Report:
    def __init__(self):
        self.ok, self.why, self.calls, self.fallbacks, self.notes = False, "", {}, {}, []

    def __str__(self):
        names = ", ".join(f"{n} {c}" for n, c in sorted(self.calls.items(), key=lambda x: -x[1]))
        out = [("passed" if self.ok else "REFUSED: " + self.why), f"its calls: {names or 'none seen'}"]
        if self.fallbacks:
            out.append("answered ENOSYS on an Echo, where it falls back: " + ", ".join(sorted(self.fallbacks)))
        return "\n".join(out + self.notes)


def descendants(pid):
    """PID and every process under it"""
    kids = {}
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                with open(f"/proc/{p}/stat") as f:
                    ppid = int(f.read().rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                continue
            kids.setdefault(ppid, []).append(int(p))
    out, todo = [], [pid]
    while todo:
        p = todo.pop()
        out.append(p)
        todo += kids.get(p, [])
    return out


def qemu_descriptors(pid, log, program=None):
    """qemu's own descriptors, in the process under PID that has LOG open (qemu runs the program in its own process
    and descriptor table): those to a file or a folder other than the program's own 0, 1 and 2 (the program cannot
    open one: every open is refused, and named, by the table).  -> (the descriptors, qemu's pid, those of them that
    are PROGRAM's file: qemu's loader may still hold it when this looks, and gives it back before the guest's first
    call; Loader.settle looks at those again), or None while that process is not there"""
    try:
        want = os.stat(log)
        exe = os.stat(program) if program else None
    except OSError:
        return None
    for p in descendants(pid):
        try:
            names = os.listdir(f"/proc/{p}/fd")
        except OSError:
            continue
        st = {}
        for n in names:
            try:
                st[int(n)] = os.stat(f"/proc/{p}/fd/{n}")
            except (OSError, ValueError):
                pass
        if not any((x.st_dev, x.st_ino) == (want.st_dev, want.st_ino) for x in st.values()):
            continue
        own = {(st[f].st_dev, st[f].st_ino) for f in GIVEN[:3] if f in st}
        fds = {f for f, x in st.items() if f not in GIVEN and (stat.S_ISREG(x.st_mode) or stat.S_ISDIR(x.st_mode))
               and (x.st_dev, x.st_ino) not in own}
        return fds, p, {f for f in fds if exe and (st[f].st_dev, st[f].st_ino) == (exe.st_dev, exe.st_ino)}
    return None


class Loader:
    """qemu's descriptors to the program's own file, seen when qemu's set was taken (its loader had it open: qemu
    opens the file, maps it and closes it before the guest runs).  Looked at again after each read of the log and
    before its lines are judged: one no longer that file is qemu's no more (qemu gave it back before any call those
    lines name, and the number may be the program's by now).  One that stays that file stays qemu's"""
    def __init__(self, pid, fds, program):
        self.pid, self.fds, self.program = pid, set(fds), program

    def settle(self, qemu):
        """QEMU (qemu's own set) without those of self.fds that are no longer the program's file"""
        if not self.fds:
            return
        try:
            exe = os.stat(self.program)
        except OSError:
            return
        gone = set()
        for f in self.fds:
            try:
                x = os.stat(f"/proc/{self.pid}/fd/{f}")
                if (x.st_dev, x.st_ino) != (exe.st_dev, exe.st_ino):
                    gone.add(f)
            except OSError:
                gone.add(f)
        # (looked at after the descriptors: a qemu that has ended, or is ending, has none, which says nothing of what
        # it held while it wrote the lines still to be judged)
        try:
            with open(f"/proc/{self.pid}/stat") as f:
                alive = f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
        except (OSError, IndexError):
            alive = False
        if alive:
            self.fds -= gone
            qemu -= gone


def run(program, manifest, qemu, seconds=3, prefix=(), work=None):
    """PROGRAM (the ARM ELF) with MANIFEST (the dict) against the stand-in broker.  PREFIX: what runs qemu (the
    sandbox, tools/sandbox.py); WORK: a folder for qemu's log and the program's stderr (one of its own,
    made and kept by the caller).  -> Report (one that did not start is refused: why sandbox.NO_USERNS where
    there is no user namespace for its bounds, and nothing of the run is left)"""
    rep = Report()
    own = work is None
    work = work or tempfile.mkdtemp(prefix="harness-")
    log, err = os.path.join(work, "strace.log"), os.path.join(work, "stderr.log")
    open(log, "w").close()
    broker, plugin = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    fd = plugin.fileno()
    # the plugin's end as its descriptor 3, as the launcher gives it (sh moves it: the sandbox passes it on as it is)
    argv = list(prefix) + ["/bin/sh", "-c", f'exec "$0" -D "$1" -strace "$2" 3<&{fd} {fd}<&-', qemu, log, program]
    try:
        with open(err, "wb") as e:
            # (an environment of its own: nothing of the job's reaches the plugin, as nothing of hassmic's does.  Under
            # sandbox.LIMITS["harness"]: its log and its stderr end it past their size; a group of its own, ended whole)
            proc = subprocess.Popen(argv, pass_fds=(fd,), stdin=subprocess.DEVNULL, stdout=e, stderr=e, cwd=work, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                    start_new_session=True, preexec_fn=sandbox.bounded("harness"))
    except (OSError, subprocess.SubprocessError) as x:
        # (not started: refused as sandbox.run refuses it, and nothing of the run left behind.  SubprocessError: the
        # child's preexec_fn raised, sandbox.bounded with no user namespace of its own to be had)
        plugin.close()
        broker.close()
        rep.why = (sandbox.NO_USERNS if isinstance(x, subprocess.SubprocessError) else f"not started: {x}")
        if own:
            shutil.rmtree(work, ignore_errors=True)
        return rep
    plugin.close()
    trace, logf, pid = Trace(), open(log, "r", errors="replace"), [None]
    trace.qemu, unseen, loader = None, [False], [None]  # (until qemu's own descriptors are seen)
    stored, store_ok = {}, "storage" in manifest.get("capabilities", {})
    state, started, welcomed, pings, stop_at, sent, rate = "hello", time.monotonic(), None, {}, None, 0, []

    def refuse(why):
        rep.why = rep.why or why
        raise StopIteration

    def look(last=False):
        if trace.qemu is None:
            # qemu's descriptors, before a line is judged: the program's own are counted from them
            got = qemu_descriptors(proc.pid, log, program)
            if got is None:
                if proc.poll() is None and not last:
                    if time.monotonic() - started > 10:
                        refuse("the harness cannot see qemu's descriptors (/proc)")
                    return
                trace.qemu, unseen[0] = set(), True     # (judged for the reasons it gives, and refused after them)
            else:
                trace.qemu, qpid, held = got
                loader[0] = Loader(qpid, held, program)
        last = last or proc.poll() is not None
        while True:
            more = logf.read(1 << 20)
            if loader[0]:
                loader[0].settle(trace.qemu)            # (after the read, before its lines are judged)
            calls = trace.feed(more) if more else []
            if last and not more:
                calls += trace.finish()
            judge(calls)
            if trace.broken:
                refuse(f"qemu's log does not read as qemu writes it (a plugin that writes into it?): {trace.broken}")
            if not more:
                break
        if unseen[0]:
            refuse("it ended before the harness saw qemu's descriptors")

    def judge(calls):
        for p, name, nr, args, shown, foreign in calls:
            pid[0] = pid[0] or p
            rep.calls[name] = rep.calls.get(name, 0) + 1
            got, why = verdict(name, nr, args, pid[0] if pid[0] is not None else p)
            if got == "enosys":
                rep.fallbacks[name] = why
            elif got != "allow":
                refuse(f"a system call the sandbox refuses: {shown}: {why}")
            if foreign:
                refuse(f"a system call on a descriptor that is not the plugin's: {shown}: {foreign}")

    def send(kind, mid, body=b""):
        try:
            broker.send(packet(kind, mid, body))
        except OSError as x:
            refuse(f"its control socket: {x}")

    def answer(kind, mid, b):
        nonlocal state
        if kind == PONG:
            pings.pop(mid, None)
        elif kind == READY:
            if state != "config":
                refuse("READY out of its place")
            state = "run"
        elif kind == STORE_GET and store_ok:
            key, _ = rs(b, 0)
            v = stored.get(key)
            send(STORE_VALUE, mid, s(v)) if v is not None else send(ERR, mid, struct.pack("<H", ERR_NOT_FOUND))
        elif kind == STORE_PUT and store_ok:
            key, at = rs(b, 0)
            stored[key], _ = rs(b, at)
            send(OK, mid)
        elif kind == STORE_DEL and store_ok:
            key, _ = rs(b, 0)
            send(OK, mid) if stored.pop(key, None) is not None else send(ERR, mid, struct.pack("<H", ERR_NOT_FOUND))
        elif kind == CONNECT and state == "run" and stop_at is None:
            send(ERR, mid, struct.pack("<H", ERR_UNSET))                # no server entered
        elif kind in (OK, ERR):
            pass                                                        # (an answer to a LOG; none is sent here)
        elif mid:
            send(ERR, mid, struct.pack("<H", ERR_BAD if state != "run" else ERR_FAILED))

    try:
        while True:
            now = time.monotonic()
            look()
            r = proc.poll()
            if r is not None:
                look(last=True)
                if stop_at is None:
                    refuse(f"it ended by itself (status {r}) before STOP" + ("" if state == "run" else ", without READY"))
                if r < 0:
                    refuse(f"it ended by signal {-r} after STOP")
                if r:
                    rep.notes.append(f"note: it ended with status {r} after STOP")
                break
            if state == "hello" and now - started > 10:
                refuse("no HELLO within 10 s of its start")
            if state == "config" and now - welcomed > 10:
                refuse("no READY within 10 s of WELCOME")
            if state == "run" and stop_at is None:
                if any(now - at > 5 for at in pings.values()):
                    refuse("a PING unanswered for 5 s")
                if now - welcomed > sent + 1 and sent < seconds:
                    sent += 1
                    pings[1000 + sent] = now
                    send(PING, 1000 + sent)
                elif sent >= seconds and not pings:
                    stop_at = now
                    send(STOP, 0)
            if stop_at is not None and now - stop_at > 2:
                refuse("still running 2 s after STOP (an Echo sends SIGTERM then)")
            if not select.select([broker], [], [], 0.05)[0]:
                continue
            try:
                d = broker.recv(MAX_PACKET + 1)
            except OSError:
                d = b""
            if not d:
                continue                                                # (its end closed: proc.poll says the rest)
            rate[:] = [t for t in rate if now - t < 1] + [now]
            if len(rate) > 1000:
                refuse("over 1000 messages in a second (an Echo stops a plugin at that)")
            if len(d) < 8 or len(d) > MAX_PACKET:
                refuse(f"a packet of {len(d)} bytes, which is no message")
            kind, flags, mid = struct.unpack_from("<HHI", d)
            if kind not in FROM_PLUGIN or flags:
                refuse(f"a message of type {kind} (flags {flags}), which a plugin does not send")
            if state == "hello":
                if kind != HELLO:
                    refuse(f"its first message is type {kind}, not HELLO")
                try:
                    offered = hello_scopes(d)
                except (ValueError, struct.error) as x:
                    refuse(f"its HELLO does not read: {x}")
                required = manifest.get("requires", {})
                lacks = [f"{k} {n}" for k, n in required.items() if offered is not None and offered.get(k, 0) < n]
                if lacks or offered is None:
                    send(REFUSED, mid, struct.pack("<H", REFUSED_SCOPES))
                    refuse("its HELLO names a scope twice" if offered is None else
                           f"its client does not speak {', '.join(lacks)}, which its manifest requires: it was built with an older SDK than its manifest says")
                # (what is spoken from here on: exactly the manifest's requires, as hassmic answers; that is also what
                # was granted, core and each capability's scope: WELCOME has no set of bits for it)
                send(WELCOME, mid, struct.pack("<I", 1) + s("Echo (the index's harness)") + s("harness") + s("Harness") + s("UTC")
                     + struct.pack("<H", len(required)) + b"".join(s(k) + struct.pack("<H", n) for k, n in required.items()))
                for row in manifest.get("settings", []):
                    if row.get("type") == "files":
                        send(FILES, 0, s(row["name"]) + struct.pack("<H", 0))
                rows = [r for r in manifest.get("settings", []) if r.get("type") != "files"]
                send(CONFIG, 0, struct.pack("<H", len(rows)) + b"".join(s(r["name"]) + s(config_value(r)) for r in rows))
                state, welcomed = "config", time.monotonic()
                continue
            try:
                answer(kind, mid, d[8:])
            except (ValueError, struct.error) as x:
                refuse(f"a message of type {kind} that does not read: {x}")
        rep.ok = True
    except StopIteration:
        pass
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        proc.wait()
        if trace.qemu is not None:
            try:
                look()                              # (what came after: shown, never a reason any more)
            except StopIteration:
                pass
        logf.close()
        broker.close()
        tail = sandbox.tail(err, 1500)            # (from its end only, its lines made harmless for a CI log)
        if not rep.ok and tail.strip():
            rep.notes.append("its stderr (the end):\n" + tail)
        if own:
            for n in (log, err):
                os.unlink(n)
            os.rmdir(work)
    return rep


def find_qemu(given=None):
    """qemu-arm: GIVEN, $INDEX_QEMU, on PATH, or hassmic's toolchain/qemu-arm beside this tree; None"""
    import shutil
    for q in (given, os.environ.get("INDEX_QEMU"), shutil.which("qemu-arm"),
              os.path.join(os.path.dirname(os.path.dirname(HERE)), "echo-dot-assist", "toolchain", "qemu-arm")):
        if q and os.path.isfile(q) and os.access(q, os.X_OK):
            return os.path.abspath(q)
    return None


def main():
    a = sys.argv[1:]
    opt = {}
    for name in ("--qemu", "--seconds"):
        if name in a:
            i = a.index(name)
            if i + 1 >= len(a):
                sys.exit(__doc__)
            opt[name] = a[i + 1]
            del a[i:i + 2]
    if len(a) != 2 or not re.fullmatch(r"[0-9]{1,3}", opt.get("--seconds", "3")):
        sys.exit(__doc__)
    qemu = find_qemu(opt.get("--qemu"))
    if not qemu:
        sys.exit("harness: no qemu-arm (install qemu-user, or --qemu, or INDEX_QEMU)")
    with open(a[1], "rb") as f:
        m = json.load(f)
    rep = run(os.path.abspath(a[0]), m, qemu, int(opt.get("--seconds", "3")))
    print(rep)
    sys.exit(0 if rep.ok else 1)


if __name__ == "__main__":
    main()
