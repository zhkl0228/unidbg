package com.github.unidbg.linux;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.linux.file.DirectoryFileIO;
import com.github.unidbg.linux.file.EventFD;
import com.github.unidbg.linux.file.PipedReadFileIO;
import com.github.unidbg.linux.file.PipedWriteFileIO;
import com.github.unidbg.linux.signal.SigAction;
import com.github.unidbg.linux.signal.SignalFunction;
import com.github.unidbg.linux.signal.SignalTask;
import com.github.unidbg.linux.struct.StatFS;
import com.github.unidbg.linux.struct.StatFS32;
import com.github.unidbg.linux.struct.StatFS64;
import com.github.unidbg.linux.thread.FutexIndefinitelyWaiter;
import com.github.unidbg.linux.thread.FutexNanoSleepWaiter;
import com.github.unidbg.linux.thread.FutexWaiter;
import com.github.unidbg.linux.thread.MarshmallowThread;
import com.github.unidbg.linux.thread.NanoSleepWaiter;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.UnixSigSet;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.thread.MainTask;
import com.github.unidbg.thread.RunnableTask;
import com.github.unidbg.thread.Task;
import com.github.unidbg.thread.ThreadContextSwitchException;
import com.github.unidbg.thread.ThreadDispatcher;
import com.github.unidbg.thread.ThreadTask;
import com.github.unidbg.thread.Waiter;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.unix.struct.TimeSpec;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import net.dongliu.apk.parser.utils.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class AndroidSyscallHandler extends UnixSyscallHandler<AndroidFileIO> implements SyscallHandler<AndroidFileIO> {

    private static final Logger log = LoggerFactory.getLogger(AndroidSyscallHandler.class);

    static final int MREMAP_MAYMOVE = 1;
    static final int MREMAP_FIXED = 2;

    private byte[] sched_cpu_mask;

    final int mlock(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer addr = context.getPointerArg(0);
        int len = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("mlock addr={}, len={}", addr, len);
        }
        return 0;
    }

    final int munlock(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer addr = context.getPointerArg(0);
        int len = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("munlock addr={}, len={}", addr, len);
        }
        return 0;
    }

    final long sched_setaffinity(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        int cpusetsize = context.getIntArg(1);
        Pointer mask = context.getPointerArg(2);
        if (mask != null) {
            sched_cpu_mask = mask.getByteArray(0, cpusetsize);
        }
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(sched_cpu_mask, "sched_setaffinity pid=" + pid + ", cpusetsize=" + cpusetsize + ", mask=" + mask));
        }
        return 0;
    }

    final long sched_getaffinity(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        int cpusetsize = context.getIntArg(1);
        Pointer mask = context.getPointerArg(2);
        int ret = 0;
        if (mask != null && sched_cpu_mask != null) {
            mask.write(0, sched_cpu_mask, 0, cpusetsize);
            ret = cpusetsize;
        }
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(sched_cpu_mask, "sched_getaffinity pid=" + pid + ", cpusetsize=" + cpusetsize + ", mask=" + mask));
        }
        return ret;
    }

    private static final int EFD_SEMAPHORE = 1;
    private static final int EFD_NONBLOCK = IOConstants.O_NONBLOCK;
    private static final int EFD_CLOEXEC = IOConstants.O_CLOEXEC;

    final int eventfd2(Emulator<?> emulator) {
        RegisterContext ctx = emulator.getContext();
        int initval = ctx.getIntArg(0);
        int flags = ctx.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("eventfd2 initval={}, flags=0x{}", initval, Integer.toHexString(flags));
        }
        if ((flags & EFD_CLOEXEC) != 0) {
            throw new UnsupportedOperationException("eventfd2 flags=0x" + Integer.toHexString(flags));
        }
        boolean nonblock = (flags & EFD_NONBLOCK) != 0;
        boolean semaphore = (flags & EFD_SEMAPHORE) != 0;
        AndroidFileIO fileIO = new EventFD(initval, semaphore, nonblock);
        int minFd = this.getMinFd();
        this.fdMap.put(minFd, fileIO);
        if (verbose) {
            System.out.printf("eventfd(%d) with flags=0x%x fd=%d from %s%n", initval, flags, minFd, emulator.getContext().getLRPointer());
        }
        return minFd;
    }

    protected int sched_setscheduler(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        int policy = context.getIntArg(1);
        Pointer param = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("sched_setscheduler pid={}, policy={}, param={}", pid, policy, param);
        }
        return 0;
    }

    protected int getcwd(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        UnidbgPointer buf = context.getPointerArg(0);
        int size = context.getIntArg(1);
        File workDir = emulator.getFileSystem().createWorkDir();
        String path = workDir.getPath();
        if (log.isDebugEnabled()) {
            log.debug("getcwd buf={}, size={}, path={}", buf, size, path);
        }
        buf.setString(0, ".");
        return (int) buf.peer;
    }

    private static final int SCHED_OTHER = 0;

    protected int sched_getscheduler(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("sched_getscheduler pid={}", pid);
        }
        return SCHED_OTHER;
    }

    protected int sched_getparam(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        Pointer param = context.getPointerArg(1);
        if (log.isDebugEnabled()) {
            log.debug("sched_getparam pid={}, param={}", pid, param);
        }
        param.setInt(0, ANDROID_PRIORITY_NORMAL);
        return 0;
    }

    protected int sched_yield(Emulator<AndroidFileIO> emulator) {
        if (log.isDebugEnabled()) {
            log.debug("sched_yield");
        }
        if (emulator.getThreadDispatcher().getTaskCount() <= 1) {
            return 0;
        } else {
            throw new ThreadContextSwitchException().setReturnValue(0);
        }
    }

    private static final int ANDROID_PRIORITY_NORMAL = 0; /* most threads run at normal priority */

    protected int getpriority(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int which = context.getIntArg(0);
        int who = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("getpriority which={}, who={}", which, who);
        }
        return ANDROID_PRIORITY_NORMAL;
    }

    protected int setpriority(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int which = context.getIntArg(0);
        int who = context.getIntArg(1);
        int prio = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("setpriority which={}, who={}, prio={}", which, who, prio);
        }
        return 0;
    }

    private static final int SIG_BLOCK = 0;
    private static final int SIG_UNBLOCK = 1;
    private static final int SIG_SETMASK = 2;

    @Override
    protected int sigprocmask(Emulator<?> emulator, int how, Pointer set, Pointer oldset) {
        Task task = emulator.get(Task.TASK_KEY);
        SignalOps signalOps = task.isMainThread() ? emulator.getThreadDispatcher() : task;
        SigSet old = signalOps.getSigMaskSet();
        if (oldset != null && old != null) {
            if (emulator.is32Bit()) {
                oldset.setInt(0, (int) old.getMask());
            } else {
                oldset.setLong(0, old.getMask());
            }
        }
        if (set == null) {
            return 0;
        }
        long mask = emulator.is32Bit() ? set.getInt(0) : set.getLong(0);
        switch (how) {
            case SIG_BLOCK:
                if (old == null) {
                    SigSet sigSet = new UnixSigSet(mask);
                    SigSet sigPendingSet = new UnixSigSet(0);
                    signalOps.setSigMaskSet(sigSet);
                    signalOps.setSigPendingSet(sigPendingSet);
                } else {
                    old.blockSigSet(mask);
                }
                return 0;
            case SIG_UNBLOCK:
                if (old != null) {
                    old.unblockSigSet(mask);
                }
                return 0;
            case SIG_SETMASK:
                SigSet sigSet = new UnixSigSet(mask);
                SigSet sigPendingSet = new UnixSigSet(0);
                signalOps.setSigMaskSet(sigSet);
                signalOps.setSigPendingSet(sigPendingSet);
                return 0;
        }
        return super.sigprocmask(emulator, how, set, oldset);
    }

    protected int rt_sigpending(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer set = context.getPointerArg(0);
        if (log.isDebugEnabled()) {
            log.debug("rt_sigpending set={}", set);
        }
        Task task = emulator.get(Task.TASK_KEY);
        SignalOps signalOps = task.isMainThread() ? emulator.getThreadDispatcher() : task;
        SigSet sigSet = signalOps.getSigPendingSet();
        if (set != null && sigSet != null) {
            if (emulator.is32Bit()) {
                set.setInt(0, (int) sigSet.getMask());
            } else {
                set.setLong(0, sigSet.getMask());
            }
        }
        return 0;
    }

    private static final int FUTEX_CMD_MASK = 0x7f;
    private static final int FUTEX_PRIVATE_FLAG = 0x80;
    private static final int MUTEX_SHARED_MASK = 0x2000;
    private static final int MUTEX_TYPE_MASK = 0xc000;
    private static final int FUTEX_WAIT = 0;
    private static final int FUTEX_WAKE = 1;
    private static final int FUTEX_FD = 2;
    private static final int FUTEX_REQUEUE = 3;
    private static final int FUTEX_CMP_REQUEUE = 4;

    public static final int ETIMEDOUT = 110;

    protected int futex(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer uaddr = context.getPointerArg(0);
        int futex_op = context.getIntArg(1);
        int val = context.getIntArg(2);
        int old = uaddr.getInt(0);
        boolean isPrivate = (futex_op & FUTEX_PRIVATE_FLAG) != 0;
        int cmd = futex_op & FUTEX_CMD_MASK;
        if (log.isDebugEnabled()) {
            log.debug("futex uaddr={}, isPrivate={}, cmd={}, val=0x{}, old=0x{}, LR={}", uaddr, isPrivate, cmd, Integer.toHexString(val), Integer.toHexString(old), context.getLRPointer());
        }

        Task task = emulator.get(Task.TASK_KEY);
        switch (cmd) {
            case FUTEX_WAIT:
                if (old != val) {
                    return -UnixEmulator.EAGAIN;
                }
                Pointer timeout = context.getPointerArg(3);
                TimeSpec timeSpec = timeout == null ? null : TimeSpec.createTimeSpec(emulator, timeout);
                int mtype = val & MUTEX_TYPE_MASK;
                int shared = val & MUTEX_SHARED_MASK;
                if (log.isDebugEnabled()) {
                    log.debug("futex FUTEX_WAIT mtype=0x{}, shared={}, timeSpec={}, test={}, task={}", Integer.toHexString(mtype), shared, timeSpec, mtype | shared, task);
                }
                RunnableTask runningTask = emulator.getThreadDispatcher().getRunningTask();
                if (threadDispatcherEnabled && runningTask != null) {
                    if (timeSpec == null) {
                        runningTask.setWaiter(emulator, new FutexIndefinitelyWaiter(uaddr, val));
                    } else {
                        runningTask.setWaiter(emulator, new FutexNanoSleepWaiter(uaddr, val, timeSpec));
                    }
                    throw new ThreadContextSwitchException();
                }
                if (threadDispatcherEnabled && emulator.getThreadDispatcher().getTaskCount() > 1) {
                    throw new ThreadContextSwitchException().setReturnValue(-ETIMEDOUT);
                } else {
                    return 0;
                }
            case FUTEX_WAKE:
                if (log.isDebugEnabled()) {
                    log.debug("futex FUTEX_WAKE val=0x{}, old={}, task={}", Integer.toHexString(val), old, task);
                }
                if (emulator.getThreadDispatcher().getTaskCount() <= 1) {
                    return 0;
                }
                int count = 0;
                for (Task t : emulator.getThreadDispatcher().getTaskList()) {
                    Waiter waiter = t.getWaiter();
                    if (waiter instanceof FutexWaiter) {
                        if (((FutexWaiter) waiter).wakeUp(uaddr)) {
                            if (++count >= val) {
                                break;
                            }
                        }
                    }
                }
                if (count > 0) {
                    throw new ThreadContextSwitchException().setReturnValue(count);
                }
                if (threadDispatcherEnabled && task != null) {
                    throw new ThreadContextSwitchException().setReturnValue(1);
                }
                return 0;
            case FUTEX_CMP_REQUEUE:
                if (log.isDebugEnabled()) {
                    log.debug("futex FUTEX_CMP_REQUEUE val=0x{}, old={}, task={}", Integer.toHexString(val), old, task);
                }
                return 0;
            default:
                if (log.isDebugEnabled()) {
                    emulator.attach().debug();
                }
                throw new AbstractMethodError("futex_op=0x" + Integer.toHexString(futex_op));
        }
    }

    protected int rt_sigtimedwait(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer set = context.getPointerArg(0);
        Pointer info = context.getPointerArg(1);
        Pointer timeout = context.getPointerArg(2);
        int sigsetsize = context.getIntArg(3);
        long mask = emulator.is32Bit() ? set.getInt(0) : set.getLong(0);
        Task task = emulator.get(Task.TASK_KEY);
        SigSet sigSet = new UnixSigSet(mask);
        SignalOps signalOps = task.isMainThread() ? emulator.getThreadDispatcher() : task;
        SigSet sigPendingSet = signalOps.getSigPendingSet();
        if (sigPendingSet != null) {
            for (Integer signum : sigSet) {
                if (sigPendingSet.containsSigNumber(signum)) {
                    sigPendingSet.removeSigNumber(signum);
                    return signum;
                }
            }
        }
        if (!task.isMainThread()) {
            throw new ThreadContextSwitchException().setReturnValue(-UnixEmulator.EINTR);
        }
        log.info("rt_sigtimedwait set={}, info={}, timeout={}, sigsetsize={}, sigSet={}, task={}", set, info, timeout, sigsetsize, sigSet, task);
        Logger log = LoggerFactory.getLogger(AbstractEmulator.class);
        if (log.isDebugEnabled()) {
            emulator.attach().debug();
        }
        return 0;
    }

    protected int rt_sigqueue(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int tgid = context.getIntArg(0);
        int sig = context.getIntArg(1);
        UnidbgPointer info = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("rt_sigqueue tgid={}, sig={}", tgid, sig);
        }
        Task task = emulator.get(Task.TASK_KEY);
        // 检查pid是有匹配进程存在
        if (!(tgid == 0 || tgid == -1 || Math.abs(tgid) == emulator.getPid())) {
            return -UnixEmulator.ESRCH;
        }
        // 检查进程是否存在, 无需发送信号
        if (sig == 0) {
            return 0;
        }
        if (sig < 0 || sig > 64) {
            return -UnixEmulator.EINVAL;
        }
        if (task != null) {
            SigAction sigAction = sigActionMap.get(sig);
            return processSignal(emulator.getThreadDispatcher(), sig, task, sigAction, info);
        }
        throw new UnsupportedOperationException();
    }

    @Override
    protected FileResult<AndroidFileIO> createFdDir(int oflags, String pathname) {
        List<DirectoryFileIO.DirectoryEntry> list = new ArrayList<>();
        for (Map.Entry<Integer, AndroidFileIO> entry : fdMap.entrySet()) {
            list.add(new DirectoryFileIO.DirectoryEntry(DirectoryFileIO.DirentType.DT_LNK, entry.getKey().toString()));
        }
        return FileResult.<AndroidFileIO>success(new DirectoryFileIO(oflags, pathname, list.toArray(new DirectoryFileIO.DirectoryEntry[0])));
    }

    @Override
    protected FileResult<AndroidFileIO> createTaskDir(Emulator<AndroidFileIO> emulator, int oflags, String pathname) {
        return FileResult.<AndroidFileIO>success(new DirectoryFileIO(oflags, pathname, new DirectoryFileIO.DirectoryEntry(false, Integer.toString(emulator.getPid()))));
    }

    protected long statfs64(Emulator<AndroidFileIO> emulator, String path, Pointer buf) {
        FileResult<AndroidFileIO> result = resolve(emulator, path, IOConstants.O_RDONLY);
        if (result == null) {
            log.info("statfs64 buf={}, path={}", buf, path);
            emulator.getMemory().setErrno(UnixEmulator.ENOENT);
            return -1;
        }
        if (result.isSuccess()) {
            StatFS statFS = emulator.is64Bit() ? new StatFS64(buf) : new StatFS32(buf);
            int ret = result.io.statfs(statFS);
            if (ret != 0) {
                log.info("statfs64 buf={}, path={}, ret={}", buf, path, ret);
            } else {
                if (verbose) {
                    System.out.printf("File statfs '%s' from %s%n", result.io, emulator.getContext().getLRPointer());
                }
                if (log.isDebugEnabled()) {
                    log.debug("statfs64 buf={}, path={}", buf, path);
                }
            }
            return ret;
        } else {
            log.info("statfs64 buf={}, path={}", buf, path);
            emulator.getMemory().setErrno(result.errno);
            return -1;
        }
    }

    protected int pipe2(Emulator<?> emulator) {
        try {
            RegisterContext context = emulator.getContext();
            Pointer pipefd = context.getPointerArg(0);
            int flags = context.getIntArg(1);
            int writefd = getMinFd();
            Pair<AndroidFileIO, AndroidFileIO> pair = getPipePair(emulator, writefd);
            this.fdMap.put(writefd, pair.getLeft());
            int readfd = getMinFd();
            this.fdMap.put(readfd, pair.getRight());
            pipefd.setInt(0, readfd);
            pipefd.setInt(4, writefd);
            if (log.isDebugEnabled()) {
                log.debug("pipe2 pipefd={}, flags=0x{}, readfd={}, writefd={}", pipefd, flags, readfd, writefd);
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return 0;
    }

    protected Pair<AndroidFileIO, AndroidFileIO> getPipePair(Emulator<?> emulator, int writefd) throws IOException {
        PipedInputStream inputStream = new PipedInputStream();
        PipedOutputStream outputStream = new PipedOutputStream(inputStream);
        AndroidFileIO writeIO = new PipedWriteFileIO(outputStream, writefd);
        AndroidFileIO readIO = new PipedReadFileIO(inputStream, writefd);
        log.info("Return default pipe pair.");
        return new Pair<>(writeIO, readIO);
    }

    protected int fchmodat(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname_p = context.getPointerArg(1);
        int mode = context.getIntArg(2);
        int flags = context.getIntArg(3);
        String pathname = pathname_p.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("fchmodat dirfd={}, pathname={}, mode=0x{}, flags=0x{}", dirfd, pathname, Integer.toHexString(mode), Integer.toHexString(flags));
        }
        return 0;
    }

    protected int fchownat(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname_p = context.getPointerArg(1);
        int owner = context.getIntArg(2);
        int group = context.getIntArg(3);
        int flags = context.getIntArg(4);
        String pathname = pathname_p.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("fchownat dirfd={}, pathname={}, owner={}, group={}, flags=0x{}", dirfd, pathname, owner, group, Integer.toHexString(flags));
        }
        return 0;
    }

    protected int mkdirat(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname_p = context.getPointerArg(1);
        int mode = context.getIntArg(2);
        String pathname = pathname_p.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("mkdirat dirfd={}, pathname={}, mode={}", dirfd, pathname, Integer.toHexString(mode));
        }
        if (dirfd != IO.AT_FDCWD) {
            throw new BackendException();
        }
        if (emulator.getFileSystem().mkdir(pathname, mode)) {
            if (log.isDebugEnabled()) {
                log.debug("mkdir pathname={}, mode={}", pathname, mode);
            }
            return 0;
        } else {
            log.info("mkdir pathname={}, mode={}", pathname, mode);
            emulator.getMemory().setErrno(UnixEmulator.EACCES);
            return -1;
        }
    }

    final int select(int nfds, Pointer checkfds, Pointer clearfds, boolean checkRead) {
        int count = 0;
        for (int i = 0; i < nfds; i++) {
            int mask = checkfds.getInt(i / 32);
            if (((mask >> i) & 1) == 1) {
                AndroidFileIO io = fdMap.get(i);
                if (!checkRead || io.canRead()) {
                    count++;
                } else {
                    mask &= ~(1 << i);
                    checkfds.setInt(i / 32, mask);
                }
            }
        }
        if (count > 0) {
            if (clearfds != null) {
                for (int i = 0; i < nfds; i++) {
                    clearfds.setInt(i / 32, 0);
                }
            }
        }
        return count;
    }

    protected int sigaltstack(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer ss = context.getPointerArg(0);
        Pointer old_ss = context.getPointerArg(1);
        if (log.isDebugEnabled()) {
            log.debug("sigaltstack ss={}, old_ss={}", ss, old_ss);
        }
        return 0;
    }

    protected int renameat(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int olddirfd = context.getIntArg(0);
        String oldpath = context.getPointerArg(1).getString(0);
        int newdirfd = context.getIntArg(2);
        String newpath = context.getPointerArg(3).getString(0);
        int ret = emulator.getFileSystem().rename(oldpath, newpath);
        if (ret != 0) {
            log.info("renameat olddirfd={}, oldpath={}, newdirfd={}, newpath={}", olddirfd, oldpath, newdirfd, newpath);
        } else {
            log.debug("renameat olddirfd={}, oldpath={}, newdirfd={}, newpath={}", olddirfd, oldpath, newdirfd, newpath);
        }
        return 0;
    }

    protected int unlinkat(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname = context.getPointerArg(1);
        int flags = context.getIntArg(2);
        emulator.getFileSystem().unlink(pathname.getString(0));
        if (log.isDebugEnabled()) {
            log.info("unlinkat dirfd={}, pathname={}, flags={}", dirfd, pathname.getString(0), flags);
        }
        return 0;
    }

    protected void exit(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int status = context.getIntArg(0);
        Task task = emulator.get(Task.TASK_KEY);
        if (task instanceof ThreadTask) {
            ThreadTask threadTask = (ThreadTask) task;
            threadTask.setExitStatus(status);
            throw new ThreadContextSwitchException().setReturnValue(0);
        }
        System.out.println("exit status=" + status);
        if (LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            emulator.attach().debug();
        }
        emulator.getBackend().emu_stop();
    }

    private static final int SIGKILL = 9;
    private static final int SIGSTOP = 19;
    private static final int SIG_ERR = -1;

    private final Map<Integer, SigAction> sigActionMap = new HashMap<>();

    @Override
    public MainTask createSignalHandlerTask(Emulator<?> emulator, int sig) {
        SigAction action = sigActionMap.get(sig);
        if (action != null) {
            return new SignalFunction(emulator, sig, action);
        }
        return super.createSignalHandlerTask(emulator, sig);
    }

    @Override
    protected int sigaction(Emulator<?> emulator, int signum, Pointer act, Pointer oldact) {
        SigAction action = SigAction.create(emulator, act);
        SigAction oldAction = SigAction.create(emulator, oldact);
        if (log.isDebugEnabled()) {
            log.debug("sigaction signum={}, action={}, oldAction={}", signum, action, oldAction);
        }
        if (SIGKILL == signum || SIGSTOP == signum) {
            if (oldAction != null) {
                oldAction.setSaHandler(SIG_ERR);
                oldAction.pack();
            }
            return -UnixEmulator.EINVAL;
        }
        SigAction lastAction = sigActionMap.put(signum, action);
        if (oldAction != null) {
            if (lastAction == null) {
                oldact.write(0, new byte[oldAction.size()], 0, oldAction.size());
            } else {
                oldAction.setSaHandler(lastAction.getSaHandler());
                oldAction.setSaRestorer(lastAction.getSaRestorer());
                oldAction.setFlags(lastAction.getFlags());
                oldAction.setMask(lastAction.getMask());
                oldAction.pack();
            }
        }
        return 0;
    }

    protected int kill(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        int sig = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("kill pid={}, sig={}", pid, sig);
        }
        if (sig == 0) {
            return 0;
        }
        if (sig < 0 || sig > 64) {
            return -UnixEmulator.EINVAL;
        }
        Task task = emulator.get(Task.TASK_KEY);
        if ((pid == 0 || pid == emulator.getPid()) && task != null) {
            SigAction action = sigActionMap.get(sig);
            return processSignal(emulator.getThreadDispatcher(), sig, task, action, null);
        }
        throw new UnsupportedOperationException("kill pid=" + pid + ", sig=" + sig + ", LR=" + context.getLRPointer());
    }

    private int processSignal(ThreadDispatcher threadDispatcher, int sig, Task task, SigAction action, Pointer sig_info) {
        if (action != null) {
            SignalOps signalOps = task.isMainThread() ? threadDispatcher : task;
            SigSet sigMaskSet = signalOps.getSigMaskSet();
            SigSet sigPendingSet = signalOps.getSigPendingSet();
            if (sigMaskSet == null || !sigMaskSet.containsSigNumber(sig)) {
                task.addSignalTask(new SignalTask(sig, action, sig_info));
                throw new ThreadContextSwitchException().setReturnValue(0);
            } else if (sigPendingSet != null) {
                sigPendingSet.addSigNumber(sig);
            }
        }
        return 0;
    }

    protected int tgkill(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int tgid = context.getIntArg(0);
        int tid = context.getIntArg(1);
        int sig = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("tgkill tgid={}, tid={}, sig={}", tgid, tid, sig);
        }
        if (sig == 0) {
            return 0;
        }
        if (sig < 0 || sig > 64) {
            return -UnixEmulator.EINVAL;
        }
        SigAction action = sigActionMap.get(sig);
        if (threadDispatcherEnabled &&
                emulator.getThreadDispatcher().sendSignal(tid, sig, action == null || action.getSaHandler() == 0L ? null : new SignalTask(sig, action))) {
            throw new ThreadContextSwitchException().setReturnValue(0);
        }
        return 0;
    }

    protected int set_tid_address(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer tidptr = context.getPointerArg(0);
        if (log.isDebugEnabled()) {
            log.debug("set_tid_address tidptr={}", tidptr);
        }
        Task task = emulator.get(Task.TASK_KEY);
        if (task instanceof MarshmallowThread) {
            MarshmallowThread thread = (MarshmallowThread) task;
            thread.set_tid_address(tidptr);
        }
        return 0;
    }

    private int threadId;

    protected final int incrementThreadId(Emulator<?> emulator) {
        if (threadId == 0) {
            threadId = emulator.getPid();
        }
        return (++threadId) & 0xffff; // http://androidxref.com/6.0.1_r10/xref/bionic/libc/bionic/pthread_mutex.cpp#215
    }

    protected int nanosleep(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer req = context.getPointerArg(0);
        Pointer rem = context.getPointerArg(1);
        TimeSpec timeSpec = TimeSpec.createTimeSpec(emulator, req);
        if (log.isDebugEnabled()) {
            log.debug("nanosleep req={}, rem={}, timeSpec={}", req, rem, timeSpec);
        }
        RunnableTask runningTask = emulator.getThreadDispatcher().getRunningTask();
        if (threadDispatcherEnabled && runningTask != null) {
            runningTask.setWaiter(emulator, new NanoSleepWaiter(emulator, rem, timeSpec));
            throw new ThreadContextSwitchException().setReturnValue(0);
        } else {
            try {
                java.lang.Thread.sleep(timeSpec.toMillis());
            } catch (InterruptedException ignored) {
            }
            return 0;
        }
    }

    protected int fallocate(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int mode = context.getIntArg(1);
        int offset = context.getIntArg(2);
        int len = context.getIntArg(3);
        if (log.isDebugEnabled()) {
            log.debug("fallocate fd={}, mode=0x{}, offset={}, len={}", fd, Integer.toHexString(mode), offset, len);
        }
        return 0;
    }

}
