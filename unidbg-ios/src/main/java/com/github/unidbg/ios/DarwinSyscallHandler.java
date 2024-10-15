package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.file.ios.IOConstants;
import com.github.unidbg.ios.kevent.KEvent;
import com.github.unidbg.ios.kevent.KEvent64;
import com.github.unidbg.ios.kevent.KEventWaiter;
import com.github.unidbg.ios.signal.SigAction;
import com.github.unidbg.ios.signal.SignalTask;
import com.github.unidbg.ios.struct.VMStatistics;
import com.github.unidbg.ios.struct.kernel.HostStatisticsReply;
import com.github.unidbg.ios.struct.kernel.HostStatisticsRequest;
import com.github.unidbg.ios.struct.kernel.MachMsgHeader;
import com.github.unidbg.ios.struct.kernel.Pthread;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.ios.struct.kernel.VprocMigLookupData;
import com.github.unidbg.ios.struct.kernel.VprocMigLookupReply;
import com.github.unidbg.ios.struct.kernel.VprocMigLookupRequest;
import com.github.unidbg.ios.thread.BsdThread;
import com.github.unidbg.ios.thread.SemWaiter;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.UnixSigSet;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.thread.RunnableTask;
import com.github.unidbg.thread.Task;
import com.github.unidbg.thread.ThreadContextSwitchException;
import com.github.unidbg.thread.ThreadDispatcher;
import com.github.unidbg.thread.ThreadTask;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.unix.struct.TimeSpec;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public abstract class DarwinSyscallHandler extends UnixSyscallHandler<DarwinFileIO> implements SyscallHandler<DarwinFileIO>, DarwinSyscall  {

    private static final Logger log = LoggerFactory.getLogger(DarwinSyscallHandler.class);

    final long bootTime = System.currentTimeMillis();

    /**
     * sysctl hw.machine
     */
    protected String getHwMachine() {
        return "iPhone6,2";
    }

    /**
     * sysctl hw.ncpu
     */
    protected int getHwNcpu() {
        return 2;
    }

    /**
     * sysctl kern.boottime
     */
    protected abstract void fillKernelBootTime(Pointer buffer);

    protected final void exit(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int status = context.getIntArg(0);
        if (status != 0 || LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            emulator.attach().debug();
        }
        System.exit(status);
    }

    protected int fork(Emulator<?> emulator) {
        log.info("fork");
        if (emulator.is64Bit()) {
            Cpsr.getArm64(emulator.getBackend()).setCarry(true);
        } else {
            Cpsr.getArm(emulator.getBackend()).setCarry(true);
        }
        return UnixEmulator.ENOSYS;
    }

    protected final int open_NOCANCEL(Emulator<DarwinFileIO> emulator, int offset) {
        RegisterContext context = emulator.getContext();
        Pointer pathname_p = context.getPointerArg(offset);
        int oflags = context.getIntArg(offset + 1);
        int mode = context.getIntArg(offset + 2);
        String pathname = pathname_p.getString(0);
        int fd = open(emulator, pathname, oflags);
        if (log.isDebugEnabled()) {
            log.debug("open_NOCANCEL pathname={}, oflags=0x{}, mode={}, fd={}, LR={}", pathname, Integer.toHexString(oflags), Integer.toHexString(mode), fd, context.getLRPointer());
        }
        if (fd == -1) {
            if (emulator.is64Bit()) {
                Cpsr.getArm64(emulator.getBackend()).setCarry(true);
            } else {
                Cpsr.getArm(emulator.getBackend()).setCarry(true);
            }
            return emulator.getMemory().getLastErrno();
        } else {
            return fd;
        }
    }

    protected int getfsstat64(Emulator<DarwinFileIO> emulator, int off) {
        RegisterContext context = emulator.getContext();
        UnidbgPointer buf = context.getPointerArg(off);
        int bufSize = context.getIntArg(off + 1);
        int flags = context.getIntArg(off + 2);
        if (log.isDebugEnabled()) {
            log.debug("getfsstat64 buf={}, bufSize={}, flags=0x{}", buf, bufSize, Integer.toHexString(flags));
        }

        final int mountedFsSize = 2;
        if (buf == null) {
            return mountedFsSize;
        }

        buf.setSize(bufSize);
        Pointer pointer = buf;
        int statfs_size = UnidbgStructure.calculateSize(StatFS.class);

        if (bufSize >= statfs_size) {
            StatFS statFS = new StatFS(pointer);
            statFS.f_bsize = 0x1000;
            statFS.f_iosize = 0x100000;
            statFS.f_blocks = 507876;
            statFS.f_bfree = 76016;
            statFS.f_bavail = 70938;
            statFS.f_files = 507874;
            statFS.f_ffree = 70938;
            statFS.f_fsid = 0x1101000002L;
            statFS.f_owner = 0;
            statFS.f_type = 0x11;
            statFS.f_flags = 0x480d000;
            statFS.f_fssubtype = 0x3;
            statFS.setFsTypeName("hfs");
            statFS.setMntOnName("/");
            statFS.setMntFromName("/dev/disk0s1s1");
            statFS.pack();

            bufSize -= statfs_size;
            pointer = pointer.share(statfs_size);
        }

        if (bufSize >= statfs_size) {
            StatFS statFS = new StatFS(pointer);
            statFS.f_bsize = 0x1000;
            statFS.f_iosize = 0x100000;
            statFS.f_blocks = 3362844;
            statFS.f_bfree = 3000788;
            statFS.f_bavail = 3000788;
            statFS.f_files = 3362842;
            statFS.f_ffree = 3000788;
            statFS.f_fsid = 0x1101000003L;
            statFS.f_owner = 0;
            statFS.f_type = 0x11;
            statFS.f_flags = 0x14809080;
            statFS.f_fssubtype = 0x3;
            statFS.setFsTypeName("hfs");
            statFS.setMntOnName("/private/var");
            statFS.setMntFromName("/dev/disk0s1s2");
            statFS.pack();
        }
        if (verbose) {
            System.out.printf("getfsstat from %s%n", emulator.getContext().getLRPointer());
        }

        return mountedFsSize;
    }

    protected final int access(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pathname = context.getPointerArg(0);
        int mode = context.getIntArg(1);
        String path = pathname.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("access pathname={}, mode={}", path, mode);
        }
        return faccessat(emulator, path, mode);
    }

    protected final int faccessat(Emulator<DarwinFileIO> emulator, String pathname, int mode) {
        FileResult<?> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            if (verbose) {
                System.out.printf("File access '%s' with mode=0x%x from %s%n", pathname, mode, emulator.getContext().getLRPointer());
            }
            return 0;
        }

        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.ENOENT);
        if (verbose) {
            System.out.printf("File access failed '%s' with mode=0x%x from %s%n", pathname, mode, emulator.getContext().getLRPointer());
        }
        return -1;
    }

    protected final int flistxattr(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        UnidbgPointer namebuf = context.getPointerArg(1);
        int size = context.getIntArg(2);
        int options = context.getIntArg(3);
        DarwinFileIO io = fdMap.get(fd);
        if (namebuf != null) {
            namebuf.setSize(size);
        }
        if (io != null) {
            int ret = io.listxattr(namebuf, size, options);
            if (ret == -1) {
                log.info("flistxattr fd={}, namebuf={}, size={}, options={}, LR={}", fd, namebuf, size, options, context.getLRPointer());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("flistxattr fd={}, namebuf={}, size={}, options={}, LR={}", fd, namebuf, size, options, context.getLRPointer());
                }
            }
            return ret;
        } else {
            log.info("flistxattr fd={}, namebuf={}, size={}, options={}, LR={}", fd, namebuf, size, options, context.getLRPointer());
            emulator.getMemory().setErrno(UnixEmulator.ENOENT);
            return -1;
        }
    }

    protected final int listxattr(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        UnidbgPointer namebuf = context.getPointerArg(1);
        int size = context.getIntArg(2);
        int options = context.getIntArg(3);
        String pathname = path.getString(0);
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (namebuf != null) {
            namebuf.setSize(size);
        }
        if (result.isSuccess()) {
            int ret = result.io.listxattr(namebuf, size, options);
            if (ret == -1) {
                log.info("listxattr path={}, namebuf={}, size={}, options={}, LR={}", pathname, namebuf, size, options, context.getLRPointer());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("listxattr path={}, namebuf={}, size={}, options={}, LR={}", pathname, namebuf, size, options, context.getLRPointer());
                }
            }
            return ret;
        } else {
            log.info("listxattr path={}, namebuf={}, size={}, options={}, LR={}", pathname, namebuf, size, options, context.getLRPointer());
            emulator.getMemory().setErrno(UnixEmulator.ENOENT);
            return -1;
        }
    }

    protected final int fchmodx_np(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int fsowner = context.getIntArg(1);
        int fsgrp = context.getIntArg(2);
        int fsmode = context.getIntArg(3);
        int fsacl = context.getIntArg(4);
        DarwinFileIO io = fdMap.get(fd);
        log.debug("fchmodx_np fd={}, fsowner={}, fsgrp={}, fsmode=0x{}, fsacl={}, io={}", fd, fsowner, fsgrp, Integer.toHexString(fsmode), fsacl, io);
        if (io != null) {
            int ret = io.chmod(fsmode);
            if (ret == -1) {
                log.info("fchmodx_np fd={}, fsmode=0x{}, io={}", fd, Integer.toHexString(fsmode), io);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("fchmodx_np fd={}, fsmode=0x{}", fd, Integer.toHexString(fsmode));
                }
            }
            return ret;
        } else {
            log.info("fchmodx_np fd={}, fsmode=0x{}", fd, Integer.toHexString(fsmode));
            Cpsr.getArm64(emulator.getBackend()).setCarry(true);
            return UnixEmulator.ENOENT;
        }
    }

    protected final int chmodx_np(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        int fsowner = context.getIntArg(1);
        int fsgrp = context.getIntArg(2);
        int fsmode = context.getIntArg(3);
        int fsacl = context.getIntArg(4);
        String pathname = path.getString(0);
        log.debug("chmodx_np pathname={}, fsowner={}, fsgrp={}, fsmode=0x{}, fsacl={}", pathname, fsowner, fsgrp, Integer.toHexString(fsmode), fsacl);
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result.isSuccess()) {
            int ret = result.io.chmod(fsmode);
            if (ret == -1) {
                log.info("chmodx_np path={}, fsmode=0x{}, io={}", pathname, Integer.toHexString(fsmode), result.io);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("chmodx_np path={}, fsmode=0x{}", pathname, Integer.toHexString(fsmode));
                }
            }
            return ret;
        } else {
            log.info("chmodx_np path={}, fsmode=0x{}", pathname, Integer.toHexString(fsmode));
            Cpsr.getArm64(emulator.getBackend()).setCarry(true);
            return UnixEmulator.ENOENT;
        }
    }

    protected int fchmod(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int mode = context.getIntArg(1) & 0xffff;
        DarwinFileIO io = fdMap.get(fd);
        if (io != null) {
            int ret = io.chmod(mode);
            if (ret == -1) {
                log.info("fchmod fd={}, mode=0x{}, io={}", fd, Integer.toHexString(mode), io);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("fchmod fd={}, mode=0x{}", fd, Integer.toHexString(mode));
                }
            }
            return ret;
        } else {
            log.info("fchmod fd={}, mode=0x{}", fd, Integer.toHexString(mode));
            Cpsr.getArm64(emulator.getBackend()).setCarry(true);
            return UnixEmulator.ENOENT;
        }
    }

    protected final int select(int nfds, Pointer checkfds, Pointer clearfds, boolean checkRead) {
        int count = 0;
        for (int i = 0; i < nfds; i++) {
            int mask = checkfds.getInt(i / 32);
            if (((mask >> i) & 1) == 1) {
                DarwinFileIO io = fdMap.get(i);
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

    protected final int chmod(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        int mode = context.getIntArg(1) & 0xffff;
        String pathname = path.getString(0);
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result.isSuccess()) {
            int ret = result.io.chmod(mode);
            if (ret == -1) {
                log.info("chmod path={}, mode=0x{}, io={}", pathname, Integer.toHexString(mode), result.io);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("chmod path={}, mode=0x{}", pathname, Integer.toHexString(mode));
                }
            }
            return ret;
        } else {
            log.info("chmod path={}, mode=0x{}", pathname, Integer.toHexString(mode));
            Cpsr.getArm64(emulator.getBackend()).setCarry(true);
            return UnixEmulator.ENOENT;
        }
    }

    protected final boolean host_statistics(Pointer request, MachMsgHeader header) {
        HostStatisticsRequest args = new HostStatisticsRequest(request);
        args.unpack();
        if (log.isDebugEnabled()) {
            log.debug("host_statistics args={}", args);
        }

        if (args.flavor == HostStatisticsRequest.HOST_VM_INFO) {
            int size = UnidbgStructure.calculateSize(VMStatistics.class);
            HostStatisticsReply reply = new HostStatisticsReply(request, size);
            reply.unpack();

            header.setMsgBits(false);
            header.msgh_size = header.size() + reply.size();
            header.msgh_remote_port = header.msgh_local_port;
            header.msgh_local_port = 0;
            header.msgh_id += 100; // reply Id always equals reqId+100
            header.pack();

            reply.writeVMStatistics();
            reply.retCode = 0;
            reply.host_info_outCnt = size / 4;
            reply.pack();

            if (log.isDebugEnabled()) {
                log.debug("host_statistics HOST_VM_INFO reply={}", reply);
            }
            return true;
        }

        return false;
    }

    final int vproc_mig_look_up2(Pointer request, MachMsgHeader header) {
        VprocMigLookupRequest args = new VprocMigLookupRequest(request);
        args.unpack();
        String serviceName = args.getServiceName();
        if (log.isDebugEnabled()) {
            log.debug("vproc_mig_look_up2 args={}, serviceName={}", args, serviceName);
        }

        if ("cy:com.saurik.substrated".equals(serviceName)) {
            return -1;
        }

        VprocMigLookupReply reply = new VprocMigLookupReply(request);
        reply.unpack();

        header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
        header.msgh_size = header.size() + reply.size();
        header.msgh_remote_port = header.msgh_local_port;
        header.msgh_local_port = 0;
        header.msgh_id += 100; // reply Id always equals reqId+100
        header.pack();

        reply.body.msgh_descriptor_count = 1;
        reply.sp.name = STATIC_PORT;
        reply.sp.pad1 = 0;
        reply.sp.pad2 = 0;
        reply.sp.disposition = 17;
        reply.sp.type = MACH_MSG_PORT_DESCRIPTOR;
        reply.pack();

        VprocMigLookupData data = new VprocMigLookupData(request.share(reply.size()));
        data.size = 0x20;
        Arrays.fill(data.au_tok.val, 0);
        data.pack();

        if (log.isDebugEnabled()) {
            log.debug("vproc_mig_look_up2 reply={}, data={}", reply, data);
        }
        return MACH_MSG_SUCCESS;
    }

    protected String executableBundlePath;

    public void setExecutableBundlePath(String executableBundlePath) {
        this.executableBundlePath = executableBundlePath;
    }

    private int threadId;

    private int incrementThreadId(Emulator<?> emulator) {
        if (threadId == 0) {
            threadId = emulator.getPid();
        }
        return (++threadId) & 0xffff;
    }

    private int processSignal(ThreadDispatcher threadDispatcher, int sig, Task task, SigAction action) {
        if (action != null) {
            SignalOps signalOps = task.isMainThread() ? threadDispatcher : task;
            SigSet sigMaskSet = signalOps.getSigMaskSet();
            SigSet sigPendingSet = signalOps.getSigPendingSet();
            if (sigMaskSet == null || !sigMaskSet.containsSigNumber(sig)) {
                task.addSignalTask(new SignalTask(sig, action));
                throw new ThreadContextSwitchException().setReturnValue(0);
            } else if (sigPendingSet != null) {
                sigPendingSet.addSigNumber(sig);
            }
        }
        return 0;
    }

    protected int pthread_kill(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int threadPort = context.getIntArg(0);
        int sig = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("pthread_kill threadPort={}, sig={}", threadPort, sig);
        }
        if (sig > 0) {
            SigAction action = sigActionMap.get(sig);
            if (emulator.getThreadDispatcher().sendSignal(threadPort, sig, action == null ? null : new SignalTask(sig, action))) {
                throw new ThreadContextSwitchException().setReturnValue(0);
            }
        }
        return 0;
    }

    protected int _semaphore_wait_trap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int port = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("_semaphore_wait_trap port={}, LR={}", port, context.getLRPointer());
        }
        if (log.isDebugEnabled()) {
            createBreaker(emulator).debug();
        }
        RunnableTask runningTask = emulator.getThreadDispatcher().getRunningTask();
        if (threadDispatcherEnabled && runningTask != null) {
            runningTask.setWaiter(emulator, new SemWaiter(port, semaphoreMap));
            throw new ThreadContextSwitchException().setReturnValue(0);
        }
        if (LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            createBreaker(emulator).debug();
        }
        return 0;
    }

    protected final Map<Integer, Boolean> semaphoreMap = new HashMap<>();

    protected int semwait_signal(Emulator<?> emulator, RunnableTask runningTask, int cond_sem, int mutex_sem, int timeout, int relative,
                                 long tv_sec, int tv_nsec) {
        if (timeout == 1 && relative == 1 && (tv_sec > 0 || tv_nsec > 0)) {
            if (threadDispatcherEnabled) {
                runningTask.setWaiter(emulator, new SemWaiter(cond_sem, semaphoreMap, tv_sec, tv_nsec));
                throw new ThreadContextSwitchException().setReturnValue(0);
            }

            try {
                Thread.sleep(tv_sec * 1000L + tv_nsec / 1000L, tv_nsec % 1000);
                emulator.getMemory().setErrno(ETIMEDOUT);
                return -1;
            } catch (InterruptedException e) {
                throw new IllegalStateException(e);
            }
        }
        if (mutex_sem != 0 || timeout != 0 ||
                relative != 0 || tv_sec != 0 || tv_nsec != 0) {
            createBreaker(emulator).debug();
            throw new UnsupportedOperationException("semwait_signal cond_sem=" + cond_sem + ", mutex_sem=" + mutex_sem + ", timeout=" + timeout + ", relative=" + relative + ", tv_sec=" + tv_sec + ", tv_nsec=" + tv_nsec);
        }
        runningTask.setWaiter(emulator, new SemWaiter(cond_sem, semaphoreMap));
        throw new ThreadContextSwitchException().setReturnValue(0);
    }

    protected int disable_threadsignal(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int status = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("disable_threadsignal status={}", status);
        }
        Task task = emulator.get(Task.TASK_KEY);
        if (task == emulator.getThreadDispatcher().getRunningTask() &&
                !task.getSignalTaskList().isEmpty()) {
            throw new ThreadContextSwitchException().setReturnValue(0);
        }
        return 0;
    }

    protected int sigpending(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer set = context.getPointerArg(0);
        if (log.isDebugEnabled()) {
            log.debug("sigpending set={}", set);
        }
        Task task = emulator.get(Task.TASK_KEY);
        SignalOps signalOps = task.isMainThread() ? emulator.getThreadDispatcher() : task;
        SigSet sigSet = signalOps.getSigPendingSet();
        if (set != null && sigSet != null) {
            set.setInt(0, (int) sigSet.getMask());
        }
        return 0;
    }

    protected int sigwait(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer set = context.getPointerArg(0);
        Pointer sig = context.getPointerArg(1);

        int mask = set.getInt(0);
        Task task = emulator.get(Task.TASK_KEY);
        SigSet sigSet = new UnixSigSet(mask);
        SignalOps signalOps = task.isMainThread() ? emulator.getThreadDispatcher() : task;
        SigSet sigPendingSet = signalOps.getSigPendingSet();
        if (sigPendingSet != null) {
            for (Integer signum : sigSet) {
                if (sigPendingSet.containsSigNumber(signum)) {
                    sigPendingSet.removeSigNumber(signum);
                    sig.setInt(0, signum);
                    return 0;
                }
            }
        }
        if (!task.isMainThread()) {
            throw new ThreadContextSwitchException().setReturnValue(-1);
        }
        log.info("sigwait set={}, sig={}", set, sig);
        Logger log = LoggerFactory.getLogger(AbstractEmulator.class);
        if (log.isDebugEnabled()) {
            emulator.attach().debug();
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
        Task task = emulator.get(Task.TASK_KEY);
        if ((pid == 0 || pid == emulator.getPid()) && sig > 0 && task != null) {
            SigAction action = sigActionMap.get(sig);
            return processSignal(emulator.getThreadDispatcher(), sig, task, action);
        }
        throw new UnsupportedOperationException("kill pid=" + pid + ", sig=" + sig + ", LR=" + context.getLRPointer());
    }

    private final Map<Integer, SigAction> sigActionMap = new HashMap<>();

    @Override
    protected int sigaction(Emulator<?> emulator, int signum, Pointer act, Pointer oldact) {
        SigAction action = SigAction.create(emulator, act);
        SigAction oldAction = SigAction.create(emulator, oldact);
        if (log.isDebugEnabled()) {
            log.debug("sigaction signum={}, action={}, oldAction={}", signum, action, oldAction);
        }
        SigAction lastAction = sigActionMap.put(signum, action);
        if (oldAction != null) {
            if (lastAction == null) {
                oldact.write(0, new byte[oldAction.size()], 0, oldAction.size());
            } else {
                oldAction.setSaHandler(lastAction.getSaHandler());
                oldAction.sa_mask = lastAction.sa_mask;
                oldAction.sa_flags = lastAction.sa_flags;
                oldAction.pack();
            }
        }
        return 0;
    }

    // https://github.com/lunixbochs/usercorn/blob/master/go/kernel/mach/thread.go
    protected int thread_selfid(Emulator<?> emulator) {
        Task task = emulator.get(Task.TASK_KEY);
        if (task != null) {
            if (task.isMainThread()) {
                return emulator.getPid();
            } else if (task instanceof ThreadTask) {
                ThreadTask thread = (ThreadTask) task;
                return thread.getId();
            }
        }
        log.debug("thread_selfid");
        return 1;
    }

    private static final int SIG_BLOCK = 1; /* block specified signal set */
    private static final int SIG_UNBLOCK = 2; /* unblock specified signal set */
    private static final int SIG_SETMASK = 3; /* set specified signal set */

    protected int pthread_sigmask(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int how = context.getIntArg(0);
        Pointer set = context.getPointerArg(1);
        Pointer oset = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("pthread_sigmask how={}, set={}, oset={}", how, set, oset);
        }

        Task task = emulator.get(Task.TASK_KEY);
        SignalOps signalOps = task.isMainThread() ? emulator.getThreadDispatcher() : task;
        SigSet old = signalOps.getSigMaskSet();
        if (oset != null && old != null) {
            oset.setInt(0, (int) old.getMask());
        }
        if (set == null) {
            return 0;
        }
        int mask = set.getInt(0);
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
            default:
                throw new IllegalStateException();
        }
    }

    protected int kqueue() {
        if (log.isDebugEnabled()) {
            log.debug("kqueue");
        }
        int fd = getMinFd();
        fdMap.put(fd, new KEvent(0));
        return fd;
    }

    protected int guarded_kqueue_np(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer guard = context.getPointerArg(0);
        int guardFlags = context.getIntArg(1);
        KEvent64 kev = new KEvent64(guard.getPointer(0));
        kev.unpack();
        if (log.isDebugEnabled()) {
            log.debug("guarded_kqueue_np kev={}, guardFlags=0x{}, LR={}", kev, Integer.toHexString(guardFlags), context.getLRPointer());
        }
        int fd = getMinFd();
        fdMap.put(fd, new KEvent(guardFlags));
        return fd;
    }

    protected int kevent64(Emulator<?> emulator, int kq, Pointer changelist, int nchanges, Pointer eventlist, int nevents, int flags, TimeSpec timeSpec) {
        RegisterContext context = emulator.getContext();
        if (log.isDebugEnabled()) {
            log.debug("kevent64 kq={}, changelist={}, nchanges={}, eventlist={}, nevents={}, flags=0x{}, timeSpec={}, LR={}", kq, changelist, nchanges, eventlist, nevents, Integer.toHexString(flags), timeSpec, context.getLRPointer());
        }
        if (timeSpec != null) {
            throw new UnsupportedOperationException();
        }
        KEvent event = (KEvent) fdMap.get(kq);
        event.processChangeList(changelist, nchanges);
        if (eventlist == null || nevents <= 0) {
            return 0;
        }
        RunnableTask runningTask = emulator.getThreadDispatcher().getRunningTask();
        if (runningTask != null) {
            runningTask.setWaiter(emulator, new KEventWaiter(event, eventlist, nevents));
            throw new ThreadContextSwitchException();
        }
        if (log.isDebugEnabled() || LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            createBreaker(emulator).debug();
        }
        return 0;
    }

    protected int psynch_cvbroad(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer ocond = context.getPointerArg(0);
        if (log.isDebugEnabled()) {
            log.debug("psynch_cvbroad ocond={}", ocond);
        }
        if (threadDispatcherEnabled) {
            throw new ThreadContextSwitchException().setReturnValue(0);
        }
        return 0;
    }

    private UnidbgPointer thread_start;
    private int pthreadSize;

    protected int bsdthread_register(UnidbgPointer thread_start, int pthreadSize) {
        this.thread_start = thread_start;
        this.pthreadSize = pthreadSize;
        return 0;
    }

    protected int bsdthread_terminate(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        final UnidbgPointer freeaddr = context.getPointerArg(0);
        final int freesize = context.getIntArg(1);
        int kport = context.getIntArg(2);
        int joinsem = context.getIntArg(3);
        if (log.isDebugEnabled()) {
            log.debug("bsdthread_terminate freeaddr={}, freesize={}, kport={}, joinsem={}", freeaddr, freesize, kport, joinsem);
        }
        if (joinsem != 0) {
            semaphoreMap.put(joinsem, Boolean.TRUE);
        }
        Task task = emulator.get(Task.TASK_KEY);
        if (task instanceof ThreadTask) {
            ThreadTask threadTask = (ThreadTask) task;
            threadTask.setExitStatus(0);
            emulator.getMemory().munmap(freeaddr.peer, freesize);
            throw new ThreadContextSwitchException().setReturnValue(0);
        }
        return 0;
    }

    protected long bsdthread_create(Emulator<?> emulator, UnidbgPointer start_routine, UnidbgPointer arg, UnidbgPointer stack, UnidbgPointer thread, int flags) {
        int threadId = incrementThreadId(emulator);

        if (thread == null) {
            if (thread_start == null || pthreadSize <= 0) {
                throw new IllegalStateException();
            }

            int stackSize = (int) stack.toUIntPeer();
            int pageSize = emulator.getPageAlign();
            MemoryBlock memoryBlock = emulator.getMemory().malloc(pageSize + stackSize + pthreadSize, true);
            thread = memoryBlock.getPointer().share(pageSize + stackSize, 0);

            Pthread pThread = Pthread.create(emulator, thread);
            pThread.setMachThreadSelf(threadId);
            pThread.pack();

            String msg = "bsdthread_create start_routine=" + start_routine + ", arg=" + arg + ", stack=" + stack + ", thread=" + thread + ", flags=0x" + Integer.toHexString(flags);
            if (threadDispatcherEnabled) {
                if (log.isDebugEnabled()) {
                    log.debug(msg);
                }

                if (verbose) {
                    System.out.printf("bsdthread_create start_routine=%s, stack=%s, thread=%s%n", start_routine, stack, thread);
                }
                if (log.isTraceEnabled()) {
                    createBreaker(emulator).debug();
                }

                emulator.getThreadDispatcher().addThread(new BsdThread(emulator, threadId, thread_start, thread, start_routine, arg, stackSize));
            } else {
                log.info(msg);
            }
            return thread.peer;
        } else {
            throw new UnsupportedOperationException();
        }
    }

    protected int swtch_pri(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int pri = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("swtch_pri pri={}, LR={}", pri, context.getLRPointer());
        }
        if (log.isDebugEnabled() || LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            createBreaker(emulator).debug();
        }
        return 0;
    }

    protected String getKernelOsType() {
        return "Darwin";
    }

    protected String getKernelOsRelease() {
        return "14.0.0";
    }

    protected String getKernelVersion() {
        return String.format("%s Kernel Version %s: Sun Mar 29 19:47:37 PDT 2015; root:xnu-2784.20.34~2/RELEASE_ARM64_S5L8960X", getKernelOsType(), getKernelOsRelease());
    }

    protected String getBuildVersion() {
        return "9A127";
    }

    protected String getKernelHostName() {
        return "unidbg.local";
    }

}
