package com.github.unidbg.linux;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LongJumpException;
import com.github.unidbg.StopEmulatorException;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.DriverFileIO;
import com.github.unidbg.linux.file.LocalAndroidUdpSocket;
import com.github.unidbg.linux.file.LocalSocketIO;
import com.github.unidbg.linux.file.NetLinkSocket;
import com.github.unidbg.linux.file.PipedSocketIO;
import com.github.unidbg.linux.file.SocketIO;
import com.github.unidbg.linux.file.TcpSocket;
import com.github.unidbg.linux.file.UdpSocket;
import com.github.unidbg.linux.struct.RLimit64;
import com.github.unidbg.linux.struct.Stat64;
import com.github.unidbg.linux.thread.MarshmallowThread;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.PopContextException;
import com.github.unidbg.thread.Task;
import com.github.unidbg.thread.ThreadContextSwitchException;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * <a href="http://androidxref.com/6.0.0_r5/xref/external/kernel-headers/original/uapi/asm-generic/unistd.h">unistd</a>
 */
public class ARM64SyscallHandler extends AndroidSyscallHandler {

    private static final Logger log = LoggerFactory.getLogger(ARM64SyscallHandler.class);

    private final SvcMemory svcMemory;

    public ARM64SyscallHandler(SvcMemory svcMemory) {
        super();

        this.svcMemory = svcMemory;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void hook(Backend backend, int intno, int swi, Object user) {
        Emulator<AndroidFileIO> emulator = (Emulator<AndroidFileIO>) user;
        UnidbgPointer pc = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_PC);

        if (intno == ARMEmulator.EXCP_BKPT) { // brk
            createBreaker(emulator).brk(pc, pc == null ? swi : (pc.getInt(0) >> 5) & 0xffff);
            return;
        }
        if (intno == ARMEmulator.EXCP_UDEF) {
            createBreaker(emulator).debug();
            return;
        }

        if (intno != ARMEmulator.EXCP_SWI) {
            throw new BackendException("intno=" + intno);
        }

        int NR = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue();
        String syscall = null;
        Throwable exception = null;
        try {
            if (swi == 0 && NR == 0 && backend.reg_read(Arm64Const.UC_ARM64_REG_X16).intValue() == Svc.POST_CALLBACK_SYSCALL_NUMBER) { // postCallback
                int number = backend.reg_read(Arm64Const.UC_ARM64_REG_X12).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handlePostCallback(emulator);
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi);
            }
            if (swi == 0 && NR == 0 && backend.reg_read(Arm64Const.UC_ARM64_REG_X16).intValue() == Svc.PRE_CALLBACK_SYSCALL_NUMBER) { // preCallback
                int number = backend.reg_read(Arm64Const.UC_ARM64_REG_X12).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handlePreCallback(emulator);
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi);
            }
            if (swi != 0) {
                if (swi == Arm64Svc.SVC_MAX) {
                    throw new PopContextException();
                }
                if (swi == Arm64Svc.SVC_MAX - 1) {
                    throw new ThreadContextSwitchException();
                }
                Svc svc = svcMemory.getSvc(swi);
                if (svc != null) {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, svc.handle(emulator));
                    return;
                }
                backend.emu_stop();
                throw new BackendException("svc number: " + swi);
            }

            if (log.isTraceEnabled()) {
                ARM.showRegs64(emulator, null);
            }

            if (handleSyscall(emulator, NR)) {
                return;
            }

            switch (NR) {
                case 17:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getcwd(emulator));
                    return;
                case 19:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, eventfd2(emulator));
                    return;
                case 64:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, write(emulator));
                    return;
                case 221:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, execve(emulator));
                    return;
                case 62:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, lseek(emulator));
                    return;
                case 172: // getpid
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, emulator.getPid());
                    return;
                case 178: // gettid
                    Task task = emulator.get(Task.TASK_KEY);
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, task == null ? 0 : task.getId());
                    return;
                case 129:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, kill(emulator));
                    return;
                case 29:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ioctl(emulator));
                    return;
                case 34:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mkdirat(emulator));
                    return;
                case 35:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, unlinkat(emulator));
                    return;
                case 38:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, renameat(emulator));
                    return;
                case 47:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fallocate(emulator));
                    return;
                case 53:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fchmodat(emulator));
                    return;
                case 54:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fchownat(emulator));
                    return;
                case 56:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, openat(emulator));
                    return;
                case 57:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, close(backend, emulator));
                    return;
                case 59:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pipe2(emulator));
                    return;
                case 63:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, read(backend, emulator));
                    return;
                case 24:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, dup3(emulator));
                    return;
                case 43: {
                    RegisterContext context = emulator.getContext();
                    Pointer pathPointer = context.getPointerArg(0);
                    Pointer buf = context.getPointerArg(1);
                    String path = pathPointer.getString(0);
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, statfs64(emulator, path, buf));
                    return;
                }
                case 46: {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ftruncate(emulator));
                    return;
                }
                case 134:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sigaction(emulator));
                    return;
                case 72:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pselect6(emulator));
                    return;
                case 78:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, readlinkat(emulator));
                    return;
                case 80:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fstat(backend, emulator));
                    return;
                case 83:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fdatasync(emulator));
                    return;
                case 96:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, set_tid_address(emulator));
                    return;
                case 98:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, futex(emulator));
                    return;
                case 220: {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, clone(emulator));
                    return;
                }
                case 160:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, uname(emulator));
                    return;
                case 132:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sigaltstack(emulator));
                    return;
                case 135:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sigprocmask(emulator));
                    return;
                case 32:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, flock(emulator));
                    return;
                case 66:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, writev(emulator));
                    return;
                case 101:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, nanosleep(emulator));
                    return;
                case 119:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_setscheduler(emulator));
                    return;
                case 122:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_setaffinity(emulator));
                    return;
                case 123:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_getaffinity(emulator));
                    return;
                case 124:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_yield(emulator));
                    return;
                case 136:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, rt_sigpending(emulator));
                    return;
                case 137:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, rt_sigtimedwait(emulator));
                    return;
                case 138:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, rt_sigqueue(emulator));
                    return;
                case 140:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, setpriority(emulator));
                    return;
                case 167:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, prctl(emulator));
                    return;
                case 169:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, gettimeofday(emulator));
                    return;
                case 73:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ppoll(emulator));
                    return;
                case 173:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getppid(emulator));
                    return;
                case 174: // getuid
                case 175: // geteuid
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
                    return;
                case 200:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, bind(emulator));
                    return;
                case 201:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, listen(emulator));
                    return;
                case 214:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, brk(backend, emulator));
                    return;
                case 215:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, munmap(backend, emulator));
                    return;
                case 216:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mremap(emulator));
                    return;
                case 61:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getdents64(emulator));
                    return;
                case 233:
                    syscall = "madvise";
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
                    return;
                case 25:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fcntl(emulator));
                    return;
                case 222:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mmap(backend, emulator));
                    return;
                case 226:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mprotect(backend, emulator));
                    return;
                case 227:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, msync(emulator));
                    return;
                case 93:
                    exit(emulator);
                    return;
                case 94:
                    exit_group(emulator);
                    return;
                case 113:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, clock_gettime(emulator));
                    return;
                case 117:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ptrace(emulator));
                    return;
                case 120:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_getscheduler(emulator));
                    return;
                case 121:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_getparam(emulator));
                    return;
                case 131:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, tgkill(emulator));
                    return;
                case 141:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getpriority(emulator));
                    return;
                case 163:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getrlimit64(emulator));
                    return;
                case 198:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, socket(emulator));
                    return;
                case 199:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, socketpair(emulator));
                    return;
                case 203:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, connect(emulator));
                    return;
                case 204:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getsockname(emulator));
                    return;
                case 242:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, accept4(emulator));
                    return;
                case 205:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getpeername(emulator));
                    return;
                case 206:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sendto(emulator));
                    return;
                case 207:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, recvfrom(emulator));
                    return;
                case 208:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, setsockopt(emulator));
                    return;
                case 209:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getsockopt(emulator));
                    return;
                case 228:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mlock(emulator));
                    return;
                case 278:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, gerrandom(emulator));
                    return;
                case 79:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fstatat64(emulator));
                    return;
                case 48:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, faccessat(emulator));
                    return;
            }
        } catch (StopEmulatorException e) {
            backend.emu_stop();
            return;
        } catch (LongJumpException e) {
            backend.emu_stop();
            throw e;
        } catch (Throwable e) {
            backend.emu_stop();
            exception = e;
        }

        if (exception == null && handleUnknownSyscall(emulator, NR)) {
            return;
        }

        log.warn("handleInterrupt intno={}, NR={}, svcNumber=0x{}, PC={}, LR={}, syscall={}", intno, NR, Integer.toHexString(swi), pc, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR), syscall, exception);
        if (log.isDebugEnabled()) {
            emulator.attach().debug();
        }
        if (exception instanceof RuntimeException) {
            throw (RuntimeException) exception;
        }
    }

    private static final int RLIMIT_STACK = 3; /* max stack size */

    private long getrlimit64(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int resource = context.getIntArg(0);
        Pointer ptr = context.getPointerArg(1);
        if (resource == RLIMIT_STACK) {
            RLimit64 rlimit64 = new RLimit64(ptr);
            long size = (long) Memory.STACK_SIZE_OF_PAGE * emulator.getPageAlign();
            rlimit64.rlim_cur = size;
            rlimit64.rlim_max = size;
            rlimit64.pack();
            return 0;
        } else {
            throw new UnsupportedOperationException("getrlimit64 resource=" + resource + ", rlimit64=" + ptr);
        }
    }

    private long msync(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer addr = context.getPointerArg(0);
        int len = context.getIntArg(1);
        int flags = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("msync addr={}, len={}, flags=0x{}", addr, len, Integer.toHexString(flags));
        }
        return 0;
    }

    private long fdatasync(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("fdatasync fd={}", fd);
        }
        return 0;
    }

    private long gerrandom(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer buf = context.getPointerArg(0);
        int bufSize = context.getIntArg(1);
        int flags = context.getIntArg(2);
        return getrandom(buf, bufSize, flags);
    }

    private long clone(Emulator<?> emulator) {
        Arm64RegisterContext context = emulator.getContext();
        Pointer child_stack = context.getPointerArg(1);
        if (child_stack == null &&
                context.getPointerArg(2) == null) {
            // http://androidxref.com/6.0.1_r10/xref/bionic/libc/bionic/fork.cpp#47
            return fork(emulator); // vfork
        }

        long fn = context.getXLong(5);
        long arg = context.getXLong(6);
        if (child_stack != null && child_stack.getLong(0) == fn && child_stack.getLong(8) == arg) {
            // http://androidxref.com/6.0.1_r10/xref/bionic/libc/arch-arm/bionic/__bionic_clone.S#49
            return bionic_clone(emulator);
        } else {
            return pthread_clone(emulator);
        }
    }

    private int pthread_clone(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int flags = context.getIntArg(0);
        UnidbgPointer child_stack = context.getPointerArg(1);
        List<String> list = new ArrayList<>();
        if ((flags & CLONE_VM) != 0) {
            list.add("CLONE_VM");
        }
        if ((flags & CLONE_FS) != 0) {
            list.add("CLONE_FS");
        }
        if ((flags & CLONE_FILES) != 0) {
            list.add("CLONE_FILES");
        }
        if ((flags & CLONE_SIGHAND) != 0) {
            list.add("CLONE_SIGHAND");
        }
        if ((flags & CLONE_PTRACE) != 0) {
            list.add("CLONE_PTRACE");
        }
        if ((flags & CLONE_VFORK) != 0) {
            list.add("CLONE_VFORK");
        }
        if ((flags & CLONE_PARENT) != 0) {
            list.add("CLONE_PARENT");
        }
        if ((flags & CLONE_THREAD) != 0) {
            list.add("CLONE_THREAD");
        }
        if ((flags & CLONE_NEWNS) != 0) {
            list.add("CLONE_NEWNS");
        }
        if ((flags & CLONE_SYSVSEM) != 0) {
            list.add("CLONE_SYSVSEM");
        }
        if ((flags & CLONE_SETTLS) != 0) {
            list.add("CLONE_SETTLS");
        }
        if ((flags & CLONE_PARENT_SETTID) != 0) {
            list.add("CLONE_PARENT_SETTID");
        }
        if ((flags & CLONE_CHILD_CLEARTID) != 0) {
            list.add("CLONE_CHILD_CLEARTID");
        }
        if ((flags & CLONE_DETACHED) != 0) {
            list.add("CLONE_DETACHED");
        }
        if ((flags & CLONE_UNTRACED) != 0) {
            list.add("CLONE_UNTRACED");
        }
        if ((flags & CLONE_CHILD_SETTID) != 0) {
            list.add("CLONE_CHILD_SETTID");
        }
        if ((flags & CLONE_STOPPED) != 0) {
            list.add("CLONE_STOPPED");
        }
        int threadId = incrementThreadId(emulator);

        UnidbgPointer fn = child_stack.getPointer(0);
        child_stack = child_stack.share(8, 0);
        UnidbgPointer arg = child_stack.getPointer(0);
        child_stack = child_stack.share(8, 0);

        if (threadDispatcherEnabled) {
            throw new UnsupportedOperationException();
        }

        log.info("pthread_clone child_stack={}, thread_id={}, fn={}, arg={}, flags={}", child_stack, threadId, fn, arg, list);
        Logger log = LoggerFactory.getLogger(AbstractEmulator.class);
        if (log.isDebugEnabled()) {
            emulator.attach().debug();
        }
        return threadId;
    }

    protected long fork(Emulator<?> emulator) {
        log.info("fork");
        emulator.getMemory().setErrno(UnixEmulator.ENOSYS);
        return -1;
    }

    private static final int CLONE_VM = 0x00000100;
    private static final int CLONE_FS = 0x00000200;
    private static final int CLONE_FILES = 0x00000400;
    private static final int CLONE_SIGHAND = 0x00000800;
    private static final int CLONE_PTRACE = 0x00002000;
    private static final int CLONE_VFORK = 0x00004000;
    private static final int CLONE_PARENT = 0x00008000;
    private static final int CLONE_THREAD = 0x00010000;
    private static final int CLONE_NEWNS = 0x00020000;
    private static final int CLONE_SYSVSEM = 0x00040000;
    private static final int CLONE_SETTLS = 0x00080000;
    private static final int CLONE_PARENT_SETTID = 0x00100000;
    private static final int CLONE_CHILD_CLEARTID = 0x00200000;
    private static final int CLONE_DETACHED = 0x00400000;
    private static final int CLONE_UNTRACED = 0x00800000;
    private static final int CLONE_CHILD_SETTID = 0x01000000;
    private static final int CLONE_STOPPED = 0x02000000;

    private int bionic_clone(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int flags = context.getIntArg(0);
        Pointer child_stack = context.getPointerArg(1);
        Pointer pid = context.getPointerArg(2);
        Pointer tls = context.getPointerArg(3);
        Pointer ctid = context.getPointerArg(4);
        UnidbgPointer fn = context.getPointerArg(5);
        UnidbgPointer arg = context.getPointerArg(6);
        List<String> list = new ArrayList<>();
        if ((flags & CLONE_VM) != 0) {
            list.add("CLONE_VM");
        }
        if ((flags & CLONE_FS) != 0) {
            list.add("CLONE_FS");
        }
        if ((flags & CLONE_FILES) != 0) {
            list.add("CLONE_FILES");
        }
        if ((flags & CLONE_SIGHAND) != 0) {
            list.add("CLONE_SIGHAND");
        }
        if ((flags & CLONE_PTRACE) != 0) {
            list.add("CLONE_PTRACE");
        }
        if ((flags & CLONE_VFORK) != 0) {
            list.add("CLONE_VFORK");
        }
        if ((flags & CLONE_PARENT) != 0) {
            list.add("CLONE_PARENT");
        }
        if ((flags & CLONE_THREAD) != 0) {
            list.add("CLONE_THREAD");
        }
        if ((flags & CLONE_NEWNS) != 0) {
            list.add("CLONE_NEWNS");
        }
        if ((flags & CLONE_SYSVSEM) != 0) {
            list.add("CLONE_SYSVSEM");
        }
        if ((flags & CLONE_SETTLS) != 0) {
            list.add("CLONE_SETTLS");
        }
        if ((flags & CLONE_PARENT_SETTID) != 0) {
            list.add("CLONE_PARENT_SETTID");
        }
        if ((flags & CLONE_CHILD_CLEARTID) != 0) {
            list.add("CLONE_CHILD_CLEARTID");
        }
        if ((flags & CLONE_DETACHED) != 0) {
            list.add("CLONE_DETACHED");
        }
        if ((flags & CLONE_UNTRACED) != 0) {
            list.add("CLONE_UNTRACED");
        }
        if ((flags & CLONE_CHILD_SETTID) != 0) {
            list.add("CLONE_CHILD_SETTID");
        }
        if ((flags & CLONE_STOPPED) != 0) {
            list.add("CLONE_STOPPED");
        }
        if (log.isDebugEnabled()) {
            log.debug("bionic_clone child_stack={}, pid={}, tls={}, ctid={}, fn={}, arg={}, flags={}", child_stack, pid, tls, ctid, fn, arg, list);
        }
        int threadId = incrementThreadId(emulator);
        if (threadDispatcherEnabled) {
            if (verbose) {
                System.out.printf("bionic_clone fn=%s, LR=%s%n", fn, context.getLRPointer());
            }
            emulator.getThreadDispatcher().addThread(new MarshmallowThread(emulator, fn, arg, ctid, threadId));
        }
        ctid.setInt(0, threadId);
        return threadId;
    }

    private int flock(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int operation = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("flock fd={}, operation={}", fd, operation);
        }
        return 0;
    }

    private int execve(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer filename = context.getPointerArg(0);
        Pointer argv = context.getPointerArg(1);
        Pointer envp = context.getPointerArg(2);
        assert filename != null;
        List<String> args = new ArrayList<>();
        Pointer pointer;
        while ((pointer = argv.getPointer(0)) != null) {
            args.add(pointer.getString(0));
            argv = argv.share(8);
        }
        List<String> env = new ArrayList<>();
        while ((pointer = envp.getPointer(0)) != null) {
            env.add(pointer.getString(0));
            envp = envp.share(8);
        }
        log.info("execve filename={}, args={}, env={}", filename.getString(0), args, env);
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int bind(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        int addrlen = context.getIntArg(2);
        return bind(emulator, sockfd, addr, addrlen);
    }

    private int listen(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        int backlog = context.getIntArg(1);
        return listen(emulator, sockfd, backlog);
    }

    protected int stat64(Emulator<AndroidFileIO> emulator, String pathname, Pointer statbuf) {
        FileResult<AndroidFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            return result.io.fstat(emulator, new Stat64(statbuf));
        }

        if (verbose) {
            log.info("stat64 pathname={}", pathname);
        }
        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.ENOENT);
        return -1;
    }

    private int getpeername(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        Pointer addrlen = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("getpeername sockfd={}, addr={}, addrlen={}", sockfd, addr, addrlen);
        }

        FileIO io = fdMap.get(sockfd);
        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }

        return io.getpeername(addr, addrlen);
    }

    private static final short POLLIN = 0x0001;
    private static final short POLLOUT = 0x0004;

    private int ppoll(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer fds = context.getPointerArg(0);
        int nfds = context.getIntArg(1);
        Pointer tmo_p = context.getPointerArg(2);
        Pointer sigmask = context.getPointerArg(3);
        int count = 0;
        for (int i = 0; i < nfds; i++) {
            Pointer pollfd = fds.share(i * 8L);
            int fd = pollfd.getInt(0);
            short events = pollfd.getShort(4); // requested events
            if (log.isDebugEnabled()) {
                log.debug("ppoll fds={}, nfds={}, tmo_p={}, sigmask={}, fd={}, events={}", fds, nfds, tmo_p, sigmask, fd, events);
            }
            if (fd < 0) {
                pollfd.setShort(6, (short) 0);
            } else {
                short revents = 0;
                if ((events & POLLOUT) != 0) {
                    revents = POLLOUT;
                } else if ((events & POLLIN) != 0) {
                    revents = POLLIN;
                }
                pollfd.setShort(6, revents); // returned events
                count++;
            }
        }
        return count;
    }

    private int sigprocmask(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int how = context.getIntArg(0);
        Pointer set = context.getPointerArg(1);
        Pointer oldset = context.getPointerArg(2);
        return sigprocmask(emulator, how, set, oldset);
    }

    private int ftruncate(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int length = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("ftruncate fd={}, length={}", fd, length);
        }
        FileIO file = fdMap.get(fd);
        if (file == null) {
            throw new UnsupportedOperationException();
        }
        return file.ftruncate(length);
    }

    private int sigaction(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int signum = context.getIntArg(0);
        Pointer act = context.getPointerArg(1);
        Pointer oldact = context.getPointerArg(2);

        return sigaction(emulator, signum, act, oldact);
    }

    private int pselect6(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int nfds = context.getIntArg(0);
        Pointer readfds = context.getPointerArg(1);
        Pointer writefds = context.getPointerArg(2);
        Pointer exceptfds = context.getPointerArg(3);
        Pointer timeout = context.getPointerArg(4);
        int size = (nfds - 1) / 8 + 1;
        if (log.isDebugEnabled()) {
            log.debug("pselect6 nfds={}, readfds={}, writefds={}, exceptfds={}, timeout={}, LR={}", nfds, readfds, writefds, exceptfds, timeout, context.getLRPointer());
            if (readfds != null) {
                byte[] data = readfds.getByteArray(0, size);
                Inspector.inspect(data, "readfds");
            }
            if (writefds != null) {
                byte[] data = writefds.getByteArray(0, size);
                Inspector.inspect(data, "writefds");
            }
        }
        if (exceptfds != null) {
            emulator.getMemory().setErrno(UnixEmulator.ENOMEM);
            return -1;
        }
        if (writefds != null) {
            int count = select(nfds, writefds, readfds, false);
            if (count > 0) {
                return count;
            }
        }
        if (readfds != null) {
            int count = select(nfds, readfds, writefds, true);
            if (count == 0) {
                try {
                    TimeUnit.SECONDS.sleep(1);
                } catch (InterruptedException e) {
                    throw new IllegalStateException(e);
                }
            }
            return count;
        }
        throw new AbstractMethodError("pselect6 nfds=" + nfds + ", readfds=null, writefds=" + writefds + ", exceptfds=null, timeout=" + timeout + ", LR=" + context.getLRPointer());
    }

    private int recvfrom(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer buf = context.getPointerArg(1);
        int len = context.getIntArg(2);
        int flags = context.getIntArg(3);
        Pointer src_addr = context.getPointerArg(4);
        Pointer addrlen = context.getPointerArg(5);

        log.debug("recvfrom sockfd={}, buf={}, len={}, flags={}, src_addr={}, addrlen={}", sockfd, buf, len, flags, src_addr, addrlen);
        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.recvfrom(backend, buf, len, flags, src_addr, addrlen);
    }

    private int sendto(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer buf = context.getPointerArg(1);
        int len = context.getIntArg(2);
        int flags = context.getIntArg(3);
        Pointer dest_addr = context.getPointerArg(4);
        int addrlen = context.getIntArg(5);

        return sendto(emulator, sockfd, buf, len, flags, dest_addr, addrlen);
    }

    private int connect(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        int addrlen = context.getIntArg(2);
        return connect(emulator, sockfd, addr, addrlen);
    }

    private int getsockname(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        Pointer addrlen = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("getsockname sockfd={}, addr={}, addrlen={}", sockfd, addr, addrlen);
        }
        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.getsockname(addr, addrlen);
    }

    private int accept4(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        Pointer addrlen = context.getPointerArg(2);
        int flags = context.getIntArg(3);
        return accept(emulator, sockfd, addr, addrlen, flags);
    }

    protected final int accept(Emulator<AndroidFileIO> emulator, int sockfd, Pointer addr, Pointer addrlen, int flags) {
        if (log.isDebugEnabled()) {
            log.debug("accept sockfd={}, addr={}, addrlen={}, flags={}", sockfd, addr, addrlen, flags);
        }

        AndroidFileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        AndroidFileIO newIO = file.accept(addr, addrlen);
        if (newIO == null) {
            return -1;
        } else {
            int fd = getMinFd();
            fdMap.put(fd, newIO);
            return fd;
        }
    }

    private int getsockopt(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        int level = context.getIntArg(1);
        int optname = context.getIntArg(2);
        Pointer optval = context.getPointerArg(3);
        Pointer optlen = context.getPointerArg(4);
        if (log.isDebugEnabled()) {
            log.debug("getsockopt sockfd={}, level={}, optname={}, optval={}, optlen={}", sockfd, level, optname, optval, optlen);
        }

        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.getsockopt(level, optname, optval, optlen);
    }

    private int setsockopt(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        int level = context.getIntArg(1);
        int optname = context.getIntArg(2);
        Pointer optval = context.getPointerArg(3);
        int optlen = context.getIntArg(4);
        if (log.isDebugEnabled()) {
            log.debug("setsockopt sockfd={}, level={}, optname={}, optval={}, optlen={}", sockfd, level, optname, optval, optlen);
        }

        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.setsockopt(level, optname, optval, optlen);
    }

    private int sdk;

    @Override
    public void addIOResolver(IOResolver<AndroidFileIO> resolver) {
        super.addIOResolver(resolver);

        if (resolver instanceof AndroidResolver) {
            sdk = ((AndroidResolver) resolver).getSdk();
        }
    }

    /**
     * create AF_UNIX local SOCK_STREAM
     */
    protected AndroidFileIO createLocalSocketIO(Emulator<?> emulator, int sdk) {
        return new LocalSocketIO(emulator, sdk);
    }

    private long socketpair(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int domain = context.getIntArg(0);
        int type = context.getIntArg(1) & 0x7ffff;
        int protocol = context.getIntArg(2);
        Pointer sv = context.getPointerArg(3);
        log.debug("socketpair domain={}, type={}, protocol={}, sv={}", domain, type, protocol, sv);

        if (protocol != SocketIO.AF_UNSPEC) {
            throw new UnsupportedOperationException();
        }
        if (domain == SocketIO.AF_LOCAL) {
            switch (type) {
                case SocketIO.SOCK_STREAM:
                case SocketIO.SOCK_SEQPACKET: {
                    int fd0 = getMinFd();
                    PipedSocketIO one = new PipedSocketIO(emulator);
                    fdMap.put(fd0, one);
                    int fd1 = getMinFd();
                    PipedSocketIO two = new PipedSocketIO(emulator);
                    fdMap.put(fd1, two);
                    one.connectPeer(two);
                    sv.setInt(0, fd0);
                    sv.setInt(4, fd1);
                    return 0;
                }
                default:
                    break;
            }
        }
        throw new UnsupportedOperationException("domain=" + domain + ", type=" + type + ", LR=" + context.getLRPointer());
    }

    private int socket(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int domain = context.getIntArg(0);
        int type = context.getIntArg(1) & 0x7ffff;
        int protocol = context.getIntArg(2);
        log.debug("socket domain={}, type={}, protocol={}", domain, type, protocol);

        if (protocol == SocketIO.IPPROTO_ICMP) {
            throw new UnsupportedOperationException();
        }

        int fd;
        switch (domain) {
            case SocketIO.AF_UNSPEC:
                throw new UnsupportedOperationException();
            case SocketIO.AF_LOCAL:
                switch (type) {
                    case SocketIO.SOCK_STREAM:
                        fd = getMinFd();
                        fdMap.put(fd, createLocalSocketIO(emulator, sdk));
                        return fd;
                    case SocketIO.SOCK_DGRAM:
                        fd = getMinFd();
                        fdMap.put(fd, new LocalAndroidUdpSocket(emulator));
                        return fd;
                    default:
                        emulator.getMemory().setErrno(UnixEmulator.EACCES);
                        return -1;
                }
            case SocketIO.AF_INET:
            case SocketIO.AF_INET6:
                switch (type) {
                    case SocketIO.SOCK_STREAM:
                        fd = getMinFd();
                        fdMap.put(fd, new TcpSocket(emulator));
                        return fd;
                    case SocketIO.SOCK_DGRAM:
                        fd = getMinFd();
                        fdMap.put(fd, new UdpSocket(emulator));
                        return fd;
                    case SocketIO.SOCK_RAW:
                        throw new UnsupportedOperationException();
                }
                break;
            case SocketIO.AF_NETLINK:
                switch (type) {
                    case SocketIO.SOCK_DGRAM:
                        fd = getMinFd();
                        fdMap.put(fd, new NetLinkSocket(emulator));
                        return fd;
                    case SocketIO.SOCK_RAW:
                    default:
                        throw new UnsupportedOperationException();
                }
        }
        log.info("socket domain={}, type={}, protocol={}", domain, type, protocol);
        emulator.getMemory().setErrno(UnixEmulator.EAFNOSUPPORT);
        return -1;
    }

    protected int uname(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer buf = context.getPointerArg(0);
        if (log.isDebugEnabled()) {
            log.debug("uname buf={}", buf);
        }

        final int SYS_NMLN = 65;

        Pointer sysName = buf.share(0);
        sysName.setString(0, "Linux"); /* Operating system name (e.g., "Linux") */

        Pointer nodeName = sysName.share(SYS_NMLN);
        nodeName.setString(0, "localhost"); /* Name within "some implementation-defined network" */

        Pointer release = nodeName.share(SYS_NMLN);
        release.setString(0, "1.0.0-unidbg"); /* Operating system release (e.g., "2.6.28") */

        Pointer version = release.share(SYS_NMLN);
        version.setString(0, "#1 SMP PREEMPT Thu Apr 19 14:36:58 CST 2018"); /* Operating system version */

        Pointer machine = version.share(SYS_NMLN);
        machine.setString(0, "armv8l"); /* Hardware identifier */

        Pointer domainName = machine.share(SYS_NMLN);
        domainName.setString(0, "localdomain"); /* NIS or YP domain name */

        return 0;
    }

    private int getppid(Emulator<AndroidFileIO> emulator) {
        if (log.isDebugEnabled()) {
            log.debug("getppid");
        }
        return emulator.getPid();
    }

    private void exit_group(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int status = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("exit with code: {}", status, new Exception("exit_group status=" + status));
        } else {
            System.out.println("exit with code: " + status);
        }
        if (LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            createBreaker(emulator).debug();
        }
        emulator.getBackend().emu_stop();
    }

    private int munmap(Backend backend, Emulator<?> emulator) {
        long timeInMillis = System.currentTimeMillis();
        long start = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        int length = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
        emulator.getMemory().munmap(start, length);
        if (log.isDebugEnabled()) {
            log.debug("munmap start=0x{}, length={}, offset={}", Long.toHexString(start), length, System.currentTimeMillis() - timeInMillis);
        }
        return 0;
    }

    private long mremap(Emulator<?> emulator) {
        Arm64RegisterContext context = emulator.getContext();
        UnidbgPointer old_address = context.getXPointer(0);
        int old_size = context.getXInt(1);
        int new_size = context.getXInt(2);
        int flags = context.getXInt(3);
        UnidbgPointer new_address = context.getXPointer(4);
        if (log.isDebugEnabled()) {
            log.debug("mremap old_address={}, old_size={}, new_size={}, flags={}, new_address={}", old_address, old_size, new_size, flags, new_address);
        }
        if (old_size == 0) {
            throw new BackendException("old_size is zero");
        }
        boolean fixed = (flags & MREMAP_FIXED) != 0;
        if ((flags & MREMAP_MAYMOVE) == 0) {
            throw new BackendException("flags=" + flags);
        }

        Memory memory = emulator.getMemory();
        byte[] data = old_address.getByteArray(0, old_size);
        int prot = memory.munmap(old_address.toUIntPeer(), old_size);
        final long address;
        if (fixed) {
            address = memory.mmap2(new_address.toUIntPeer(), new_size, prot, AndroidElfLoader.MAP_ANONYMOUS | AndroidElfLoader.MAP_FIXED, 0, 0);
        } else {
            address = memory.mmap2(0, new_size, prot, AndroidElfLoader.MAP_ANONYMOUS, 0, 0);
        }
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, address);
        assert pointer != null;
        pointer.write(0, data, 0, data.length);
        return pointer.toUIntPeer();
    }

    private static final int PR_SET_NAME = 15;
    private static final int PR_SET_NO_NEW_PRIVS = 38;
    private static final int PR_SET_THP_DISABLE = 41;
    private static final int BIONIC_PR_SET_VMA = 0x53564d41;
    private static final int PR_SET_PTRACER = 0x59616d61;

    private int prctl(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int option = context.getIntArg(0);
        long arg2 = context.getLongArg(1);
        if (log.isDebugEnabled()) {
            log.debug("prctl option=0x{}, arg2=0x{}", Integer.toHexString(option), Long.toHexString(arg2));
        }
        switch (option) {
            case PR_SET_NAME:
                Pointer threadName = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("prctl set thread name: {}", threadName.getString(0));
                }
                return 0;
            case BIONIC_PR_SET_VMA:
                Pointer addr = context.getPointerArg(2);
                int len = context.getIntArg(3);
                Pointer pointer = context.getPointerArg(4);
                if (log.isDebugEnabled()) {
                    log.debug("prctl set vma addr={}, len={}, pointer={}, name={}", addr, len, pointer, pointer.getString(0));
                }
                return 0;
            case PR_SET_PTRACER:
                int pid = (int) arg2;
                if (log.isDebugEnabled()) {
                    log.debug("prctl set ptracer: {}", pid);
                }
                return 0;
            case PR_SET_NO_NEW_PRIVS:
            case PR_SET_THP_DISABLE:
                return 0;
        }
        throw new UnsupportedOperationException("option=" + option);
    }

    private static final int CLOCK_REALTIME = 0;
    private static final int CLOCK_MONOTONIC = 1;
    private static final int CLOCK_MONOTONIC_RAW = 4;
    private static final int CLOCK_MONOTONIC_COARSE = 6;
    private static final int CLOCK_BOOTTIME = 7;

    private final long nanoTime = System.nanoTime();

    protected int clock_gettime(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int clk_id = context.getIntArg(0) & 0x7;
        Pointer tp = context.getPointerArg(1);
        long offset = clk_id == CLOCK_REALTIME ? currentTimeMillis() * 1000000L : System.nanoTime() - nanoTime;
        long tv_sec = offset / 1000000000L;
        long tv_nsec = offset % 1000000000L;
        if (log.isDebugEnabled()) {
            log.debug("clock_gettime clk_id={}, tp={}, offset={}, tv_sec={}, tv_nsec={}", clk_id, tp, offset, tv_sec, tv_nsec);
        }
        switch (clk_id) {
            case CLOCK_REALTIME:
            case CLOCK_MONOTONIC:
            case CLOCK_MONOTONIC_RAW:
            case CLOCK_MONOTONIC_COARSE:
            case CLOCK_BOOTTIME:
                tp.setLong(0, tv_sec);
                tp.setLong(8, tv_nsec);
                return 0;
        }
        if (log.isDebugEnabled()) {
            emulator.attach().debug();
        }
        throw new UnsupportedOperationException("clk_id=" + clk_id);
    }

    protected long ptrace(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int request = context.getIntArg(0);
        int pid = context.getIntArg(1);
        Pointer addr = context.getPointerArg(2);
        Pointer data = context.getPointerArg(3);
        log.info("ptrace request=0x{}, pid={}, addr={}, data={}", Integer.toHexString(request), pid, addr, data);
        return 0;
    }

    private int fcntl(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int cmd = context.getIntArg(1);
        int arg = context.getIntArg(2);
        return fcntl(emulator, fd, cmd, arg);
    }

    private int writev(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer iov = context.getPointerArg(1);
        int iovcnt = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            for (int i = 0; i < iovcnt; i++) {
                Pointer iov_base = iov.getPointer(i * 16L);
                long iov_len = iov.getLong(i * 16L + 8);
                byte[] data = iov_base.getByteArray(0, (int) iov_len);
                Inspector.inspect(data, "writev fd=" + fd + ", iov=" + iov + ", iov_base=" + iov_base);
            }
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }

        int count = 0;
        for (int i = 0; i < iovcnt; i++) {
            Pointer iov_base = iov.getPointer(i * 16L);
            long iov_len = iov.getLong(i * 16L + 8);
            byte[] data = iov_base.getByteArray(0, (int) iov_len);
            count += file.write(data);
        }
        return count;
    }

    private long brk(Backend backend, Emulator<?> emulator) {
        long address = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        if (log.isDebugEnabled()) {
            log.debug("brk address=0x{}", Long.toHexString(address));
        }
        return emulator.getMemory().brk(address);
    }

    private int mprotect(Backend backend, Emulator<?> emulator) {
        long address = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        int length = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
        int prot = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
        long pageAlign = emulator.getPageAlign();
        long alignedAddress = address / pageAlign * pageAlign;
        long offset = address - alignedAddress;

        long alignedLength = ARM.alignSize(length + offset, emulator.getPageAlign());
        if (log.isDebugEnabled()) {
            log.debug("mprotect address=0x{}, alignedAddress=0x{}, offset={}, length={}, alignedLength={}, prot=0x{}", Long.toHexString(address), Long.toHexString(alignedAddress), offset, length, alignedLength, Integer.toHexString(prot));
        }
        return emulator.getMemory().mprotect(alignedAddress, (int) alignedLength, prot);
    }

    private long mmap(Backend backend, Emulator<?> emulator) {
        long start = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        int length = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
        int prot = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
        int flags = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
        int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X4).intValue();
        int offset = backend.reg_read(Arm64Const.UC_ARM64_REG_X5).intValue();
        if (offset % emulator.getPageAlign() != 0) {
            throw new IllegalArgumentException("offset=0x" + Long.toHexString(offset));
        }

        boolean warning = length > 0x10000000;
        if (log.isDebugEnabled() || warning) {
            String msg = "mmap start=0x" + Long.toHexString(start) + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset;
            if (warning) {
                log.warn(msg);
                if (log.isTraceEnabled()) {
                    emulator.attach().debug();
                }
            } else {
                log.debug(msg);
            }
        }
        return emulator.getMemory().mmap2(start, length, prot, flags, fd, offset);
    }

    private int gettimeofday(Emulator<?> emulator) {
        Pointer tv = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
        Pointer tz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        return gettimeofday64(tv, tz);
    }

    private int faccessat(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname_p = context.getPointerArg(1);
        int oflags = context.getIntArg(2);
        int mode = context.getIntArg(3);
        String pathname = pathname_p.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("faccessat dirfd={}, pathname={}, oflags=0x{}, mode=0x{}", dirfd, pathname, Integer.toHexString(oflags), Integer.toHexString(mode));
        }
        int ret = faccessat(emulator, pathname);
        if (ret == -1 && verbose) {
            log.info("faccessat failed dirfd={}, pathname={}, oflags=0x{}, mode=0x{}", dirfd, pathname, Integer.toHexString(oflags), Integer.toHexString(mode));
        }
        return ret;
    }

    private int faccessat(Emulator<AndroidFileIO> emulator, String pathname) {
        FileResult<?> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            return 0;
        }

        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.EACCES);
        return -1;
    }

    private int fstatat64(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname = context.getPointerArg(1);
        Pointer statbuf = context.getPointerArg(2);
        int flags = context.getIntArg(3);
        String path = FilenameUtils.normalize(pathname.getString(0), true);
        if (log.isDebugEnabled()) {
            log.debug("fstatat64 dirfd={}, pathname={}, statbuf={}, flags={}", dirfd, path, statbuf, flags);
        }
        if (dirfd == IO.AT_FDCWD && "".equals(path)) {
            return stat64(emulator, ".", statbuf);
        }
        if (path.startsWith("/")) {
            return stat64(emulator, path, statbuf);
        } else {
            if (dirfd != IO.AT_FDCWD) {
                throw new BackendException("dirfd=" + dirfd);
            }

            log.warn("fstatat64 dirfd={}, pathname={}, statbuf={}, flags={}", dirfd, path, statbuf, flags);
            if (log.isDebugEnabled()) {
                emulator.attach().debug();
            }
            emulator.getMemory().setErrno(UnixEmulator.EACCES);
            return -1;
        }
    }

    private int openat(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname_p = context.getPointerArg(1);
        int oflags = context.getIntArg(2);
        int mode = context.getIntArg(3);
        String pathname = pathname_p.getString(0);
        log.debug("openat dirfd={}, pathname={}, oflags=0x{}, mode={}", dirfd, pathname, Integer.toHexString(oflags), Integer.toHexString(mode));
        pathname = FilenameUtils.normalize(pathname, true);
        if ("/data/misc/zoneinfo/current/tzdata".equals(pathname) || "/dev/pmsg0".equals(pathname)) {
            emulator.getMemory().setErrno(UnixEmulator.ENOENT);
            return -UnixEmulator.ENOENT;
        }
        if (pathname.startsWith("/")) {
            int fd = open(emulator, pathname, oflags);
            if (fd == -1) {
                if (verbose) {
                    log.info("openat dirfd={}, pathname={}, oflags=0x{}, mode={}", dirfd, pathname, Integer.toHexString(oflags), Integer.toHexString(mode));
                }
                return -emulator.getMemory().getLastErrno();
            } else {
                return fd;
            }
        } else {
            if (dirfd != IO.AT_FDCWD) {
                throw new BackendException();
            }

            int fd = open(emulator, pathname, oflags);
            if (fd == -1) {
                if (log.isTraceEnabled()) {
                    emulator.attach().debug();
                }
                if (verbose) {
                    log.info("openat AT_FDCWD dirfd={}, pathname={}, oflags=0x{}, mode={}", dirfd, pathname, Integer.toHexString(oflags), Integer.toHexString(mode));
                }
                return -emulator.getMemory().getLastErrno();
            } else {
                return fd;
            }
        }
    }

    private int lseek(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int offset = context.getIntArg(1);
        int whence = context.getIntArg(2);
        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int pos = file.lseek(offset, whence);
        if (log.isDebugEnabled()) {
            log.debug("lseek fd={}, offset={}, whence={}, pos={}", fd, offset, whence, pos);
        }
        return pos;
    }

    private int close(Backend backend, Emulator<?> emulator) {
        int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        if (log.isDebugEnabled()) {
            log.debug("close fd={}", fd);
        }

        return close(emulator, fd);
    }

    private int getdents64(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        UnidbgPointer dirp = context.getPointerArg(1);
        int size = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("getdents64 fd={}, dirp={}, size={}", fd, dirp, size);
        }

        AndroidFileIO io = fdMap.get(fd);
        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        } else {
            dirp.setSize(size);
            return io.getdents64(dirp, size);
        }
    }

    private int readlinkat(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname = context.getPointerArg(1);
        Pointer buf = context.getPointerArg(2);
        int bufSize = context.getIntArg(3);
        String path = pathname.getString(0);
        if (dirfd != IO.AT_FDCWD) {
            throw new BackendException();
        }
        return readlink(emulator, path, buf, bufSize);
    }

    private int fstat(Backend backend, Emulator<?> emulator) {
        int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        Pointer stat = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        return fstat(emulator, fd, stat);
    }

    protected int fstat(Emulator<?> emulator, int fd, Pointer stat) {
        AndroidFileIO file = fdMap.get(fd);
        if (file == null) {
            if (log.isDebugEnabled()) {
                log.debug("fstat fd={}, stat={}, errno=" + UnixEmulator.EBADF, fd, stat);
            }

            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        if (log.isDebugEnabled()) {
            log.debug("fstat file={}, stat={}, from={}", file, stat, emulator.getContext().getLRPointer());
        }
        return file.fstat(emulator, new Stat64(stat));
    }

    private int ioctl(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        long request = context.getLongArg(1);
        long argp = context.getLongArg(2);
        if (log.isDebugEnabled()) {
            log.debug("ioctl fd={}, request=0x{}, argp=0x{}", fd, Long.toHexString(request), Long.toHexString(argp));
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int ret = file.ioctl(emulator, request, argp);
        if (ret == -1) {
            emulator.getMemory().setErrno(UnixEmulator.ENOTTY);
        }
        return ret;
    }

    private int write(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer buffer = context.getPointerArg(1);
        int count = context.getIntArg(2);
        return write(emulator, fd, buffer, count);
    }

    private int read(Backend backend, Emulator<?> emulator) {
        int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        Pointer buffer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        int count = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
        return read(emulator, fd, buffer, count);
    }

    private int dup3(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int oldfd = context.getIntArg(0);
        int newfd = context.getIntArg(1);
        int flags = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("dup3 oldfd={}, newfd={}, flags=0x{}", oldfd, newfd, Integer.toHexString(flags));
        }

        FileIO old = fdMap.get(oldfd);
        if (old == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }

        if (oldfd == newfd) {
            return newfd;
        }
        AndroidFileIO _new = fdMap.remove(newfd);
        if (_new != null) {
            _new.close();
        }
        _new = (AndroidFileIO) old.dup2();
        fdMap.put(newfd, _new);
        return newfd;
    }

    @Override
    protected AndroidFileIO createByteArrayFileIO(String pathname, int oflags, byte[] data) {
        return new ByteArrayFileIO(oflags, pathname, data);
    }

    @Override
    protected AndroidFileIO createDriverFileIO(Emulator<?> emulator, int oflags, String pathname) {
        return DriverFileIO.create(emulator, oflags, pathname);
    }
}
