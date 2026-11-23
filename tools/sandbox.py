#!/usr/bin/env python3
"""The sandbox the harness runs a plugin's program in (tools/harness.py, index.py smoke: a community version's
package as its author's CI released it, run for its first seconds under qemu-arm; hassmic's docs/plugins.md 5.3,
5.8).  Nothing is built here: the index lists, and a plugin's own GitHub Actions build and attest it
(tools/attest.py).  What runs is a stranger's program, so it runs as the index's CI job without secrets runs it, and a
PC that runs it runs it as its user, inside this:
  - bubblewrap with every namespace of its own (no network), no home, a /tmp and /dev/shm of its own, /usr and
    /etc read-only, only the run's folder writable, nothing else of the host's files (not this repository, not its
    secrets/, nothing of the user's);
  - under bounds (LIMITS: address space, processes, file size, CPU time; the wall clock), each run in a user
    namespace of its own, where the kernel counts that run's tasks alone (own_userns), so that a program can fail
    its own version and nothing else;
  - where no process gets a user namespace here (unprivileged user namespaces off, or Ubuntu's AppArmor restriction,
    which the CI job lifts), nothing runs, and that is said (sandbox_works, NO_USERNS)."""
import os, resource, shutil, signal, subprocess, time

# Each process's bounds (setrlimit, inherited through bubblewrap into the sandbox): address space, size of any file
# it writes, CPU seconds, and "procs" processes and threads of its own.  RLIMIT_NPROC counts a user's tasks per user
# namespace (Linux 5.14 on, ucounts): set in the user namespace each run gets for itself (own_userns), it counts that
# run's tasks alone, whatever else the user runs (other runs beside it, a CI job's other steps), and a nested
# namespace (bubblewrap's) counts towards it.  qemu-arm reserves 4 GB for a 32-bit guest before the guest runs
# (measured: 6 GB starts it, 4 GB does not).  A file past "fsize" ends its writer (SIGXFSZ).  "probe": the sandbox's
# own probe (sandbox_works), and the tests' bounded runs
LIMITS = {
    "probe": {"as": 1 << 30, "fsize": 64 << 20, "cpu": 60, "procs": 256},
    "harness": {"as": 6 << 30, "fsize": 64 << 20, "cpu": 60, "procs": 256},
}


class Failed(Exception):
    pass


def find_bwrap():
    b = os.environ.get("INDEX_BWRAP") or shutil.which("bwrap")
    return b if b and os.access(b, os.X_OK) else None


_size_ok = {}
def tmpfs_size(bwrap):
    """whether this bubblewrap takes --size (0.10 and later; Ubuntu 24.04 has 0.9)"""
    if bwrap not in _size_ok:
        try:
            _size_ok[bwrap] = "--size" in subprocess.run([bwrap, "--help"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            _size_ok[bwrap] = False
    return _size_ok[bwrap]


def sandbox(bwrap, rw, ro=(), cwd=None, scratch=None, scratch_max=512 << 20):
    """bubblewrap's command line for a sandbox: every namespace of its own (no network), /usr and /etc read-only,
    a /tmp and a /dev/shm of its own, RO read-only and RW writable at their own paths, nothing else of the host's
    files.  /tmp and /dev/shm: tmpfs of SCRATCH_MAX bytes where bubblewrap can bound one, else folders in SCRATCH
    (one of RW: the bytes there are counted with the rest)"""
    a = [bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/usr", "/usr"]
    for d in ("/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32"):
        if os.path.islink(d):
            a += ["--symlink", os.readlink(d), d]
        elif os.path.isdir(d):
            a += ["--ro-bind", d, d]
    a += ["--ro-bind", "/etc", "/etc", "--proc", "/proc", "--dev", "/dev"]
    # (before the folders: one of them may be under /tmp, as a test's are)
    for inside, name in (("/tmp", "tmp"), ("/dev/shm", "shm")):
        if tmpfs_size(bwrap):
            a += ["--size", str(scratch_max), "--tmpfs", inside]
        elif scratch:
            os.makedirs(os.path.join(scratch, name), exist_ok=True)
            a += ["--bind", os.path.join(scratch, name), inside]
        else:
            raise Failed("a sandbox without a bounded /tmp: this bubblewrap has no --size, and no folder was given")
    for d in ro:
        a += ["--ro-bind", d, d]
    for d in rw:
        a += ["--bind", d, d]
    if cwd:
        a += ["--chdir", cwd]
    return a + ["--"]


def own_userns(uid, gid):
    """this process into a user namespace of its own, UID and GID mapped to themselves (nothing else of it changes:
    the same files, the same network; capabilities in it end with the exec, which runs as UID).  OSError where the
    kernel makes none (unprivileged user namespaces off: bubblewrap needs them too)"""
    if hasattr(os, "unshare"):
        os.unshare(os.CLONE_NEWUSER)
    else:                                           # (Python before 3.12)
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.unshare(0x10000000) != 0:
            raise OSError(ctypes.get_errno(), "unshare(CLONE_NEWUSER)")
    for name, text in (("setgroups", "deny"), ("uid_map", f"{uid} {uid} 1"), ("gid_map", f"{gid} {gid} 1")):
        with open(f"/proc/self/{name}", "w") as f:
            f.write(text)


def bounded(kind, cpu=None):
    """a preexec_fn that puts the process into a user namespace of its own and sets LIMITS[KIND] there (CPU: CPU
    seconds instead of its own).  Raises in the child where there is no user namespace to be had: Popen then raises
    subprocess.SubprocessError, and nothing runs without its bound"""
    lim = LIMITS[kind]
    cpu = int(cpu or lim["cpu"]) + 1
    uid, gid = os.getuid(), os.getgid()

    def go():
        own_userns(uid, gid)                        # (first: the namespace's ceiling is the limit at its making)
        for r, v in ((resource.RLIMIT_AS, lim["as"]), (resource.RLIMIT_FSIZE, lim["fsize"]), (resource.RLIMIT_CPU, cpu),
                     (resource.RLIMIT_NPROC, lim["procs"]), (resource.RLIMIT_CORE, 0)):
            soft, hard = resource.getrlimit(r)
            v = v if hard == resource.RLIM_INFINITY else min(v, hard)
            resource.setrlimit(r, (v, v))
    return go


def folder_bytes(d, most_files):
    """(bytes, files) under D, counted as far as MOST_FILES files"""
    total, files, todo = 0, 0, [d]
    while todo and files <= most_files:
        try:
            with os.scandir(todo.pop()) as it:
                for e in it:
                    files += 1
                    try:
                        if e.is_dir(follow_symlinks=False):
                            todo.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_blocks * 512
                    except OSError:
                        pass
        except OSError:
            pass
    return total, files


# why a bounded process did not start: bounded()'s preexec_fn found no user namespace to be had
NO_USERNS = "not started: no user namespace of its own for its bounds (unprivileged user namespaces off?)"


def run(argv, kind, seconds, what, out=None, env=None, cwd=None, watch=None, watch_max=0, watch_files=0, cpu=None):
    """ARGV under LIMITS[KIND], for SECONDS at most, its stdout and stderr into the file OUT (else /dev/null), in a
    process group of its own that is ended whole; WATCH: a folder whose bytes and files are looked at twice a
    second (WATCH_MAX, WATCH_FILES).  -> its exit status; Failed when a bound ended it (WHAT names the step)"""
    if seconds <= 0:
        raise Failed(f"{what}: no time left (the run's budget is spent)")
    sink = open(out, "wb") if out else open(os.devnull, "wb")
    try:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT, env=env, cwd=cwd,
                             start_new_session=True, preexec_fn=bounded(kind, cpu))
    except OSError as x:
        sink.close()
        raise Failed(f"{what}: {x}")
    except subprocess.SubprocessError:
        sink.close()
        raise Failed(f"{what}: {NO_USERNS}")
    sink.close()
    end, why = time.monotonic() + seconds, None
    try:
        while True:
            try:
                return_code = p.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                pass
            if time.monotonic() > end:
                why = f"more than {int(seconds)} s"
            elif watch:
                size, files = folder_bytes(watch, watch_files)
                if size > watch_max:
                    why = f"its folder grew past {watch_max >> 20} MB"
                elif files > watch_files:
                    why = f"its folder grew past {watch_files} files"
            if why:
                break
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.wait()
    if why:
        raise Failed(f"{what}: {why}")
    return return_code


def sandbox_works(bwrap, work):
    """None where a process under its bounds (run: a user namespace of its own) gets into BWRAP's sandbox here, else
    why not.  Neither is to be had where unprivileged user namespaces are off, or restricted (Ubuntu's AppArmor,
    kernel.apparmor_restrict_unprivileged_userns, which index.yml lifts): then no program runs, and that is the
    step's failure, never each version's.  WORK: a
    folder for the probe's own (removed after)"""
    d = os.path.join(work, "sandbox-probe")
    os.makedirs(d, exist_ok=True)
    try:
        code = run(sandbox(bwrap, [], scratch=d) + ["/bin/true"], "probe", 60, "the sandbox's probe", out=os.path.join(d, "log"))
        return None if code == 0 else f"the sandbox's probe: bubblewrap ended with status {code}:\n{tail(os.path.join(d, 'log'), 600)}"
    except Failed as x:
        return str(x)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def tail(path, most=1200):
    """the end of a log a stranger's program wrote, read from its end only, as lines nobody can take for anything
    else: control characters shown as ?, each line indented (a CI log reads a line that starts with "::" as a
    command to the runner)"""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - most))
            data = f.read(most)
    except OSError:
        return ""
    text = "".join(c if c == "\n" or " " <= c < "\x7f" or c > "\x9f" else "?" for c in data.decode(errors="replace"))
    return "\n".join("  | " + line for line in text.rstrip().splitlines())
