package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.StopEmulatorException;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.ARMEmulator;
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
import com.github.unidbg.linux.struct.Stat64;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.unix.file.SocketIO;
import com.github.unidbg.unix.file.TcpSocket;
import com.github.unidbg.unix.file.UdpSocket;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static unicorn.ArmConst.UC_ARM_REG_C13_C0_3;

/**
 * http://androidxref.com/6.0.0_r5/xref/external/kernel-headers/original/uapi/asm-generic/unistd.h
 */
public class ARM64SyscallHandler extends UnixSyscallHandler<AndroidFileIO> implements SyscallHandler<AndroidFileIO> {

    private static final Log log = LogFactory.getLog(ARM64SyscallHandler.class);

    private final SvcMemory svcMemory;

    public ARM64SyscallHandler(SvcMemory svcMemory) {
        super();

        this.svcMemory = svcMemory;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void hook(Unicorn u, int intno, Object user) {
        Emulator<AndroidFileIO> emulator = (Emulator<AndroidFileIO>) user;
        UnicornPointer pc = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_PC);

        if (intno == ARMEmulator.EXCP_BKPT) { // brk
            emulator.attach().brk(pc, (pc.getInt(0) >> 5) & 0xffff);
            return;
        }

        if (intno != ARMEmulator.EXCP_SWI) {
            throw new UnicornException("intno=" + intno);
        }

        final int svcNumber = (pc.getInt(-4) >> 5) & 0xffff;

        int NR = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X8)).intValue();
        String syscall = null;
        Throwable exception = null;
        try {
            if (svcNumber == 0 && NR == 0 && ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X16)).intValue() == Svc.CALLBACK_SYSCALL_NUMBER) { // callback
                int number = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X4)).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handleCallback(emulator);
                    return;
                }
                u.emu_stop();
                throw new IllegalStateException("svc number: " + svcNumber);
            }
            if (svcNumber != 0) {
                Svc svc = svcMemory.getSvc(svcNumber);
                if (svc != null) {
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, svc.handle(emulator));
                    return;
                }
                u.emu_stop();
                throw new UnicornException("svc number: " + svcNumber);
            }

            if (log.isDebugEnabled()) {
                ARM.showRegs64(emulator, null);
            }

            if (handleSyscall(emulator, NR)) {
                return;
            }

            switch (NR) {
                case 1888:
                    int status = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                    System.out.println("exit status=" + status);
                    u.emu_stop();
                    return;
                case 2888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, fork(emulator));
                    return;
                case 64:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, write(emulator));
                    return;
                case 5888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, open(u, emulator));
                    return;
                case 10888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, unlink(emulator));
                    return;
                case 221:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, execve(emulator));
                    return;
                case 62:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, lseek(emulator));
                    return;
                case  172: // getpid
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, emulator.getPid());
                    return;
                case 224888: // gettid
                    u.reg_write(ArmConst.UC_ARM_REG_R0, emulator.getPid());
                    return;
                case 33888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, access(u, emulator));
                    return;
                case 36888: // sync: causes all pending modifications to filesystem metadata and cached file data to be written to the underlying filesystems.
                    return;
                case 37888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, kill(u));
                    return;
                case 39888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, mkdir(u, emulator));
                    return;
                case 41888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, dup(u, emulator));
                    return;
                case 42888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, pipe(emulator));
                    return;
                case 29:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, ioctl(emulator));
                    return;
                case 56:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, openat(u, emulator));
                    return;
                case 57:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, close(u, emulator));
                    return;
                case 60888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, umask(u));
                    return;
                case 63:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, read(u, emulator));
                    return;
                case 24:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, dup3(emulator));
                    return;
                case 134:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, sigaction(emulator));
                    return;
                case 72:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, pselect6(emulator));
                    return;
                case 78:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, readlinkat(emulator));
                    return;
                case 80:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, fstat(u, emulator));
                    return;
                case 88888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, reboot(u, emulator));
                    return;
                case 93888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, ftruncate(u));
                    return;
                case 94888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, fchmod(u));
                    return;
                case 98:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, futex(u, emulator));
                    return;
                case 103888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, syslog(u, emulator));
                    return;
                case 104888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, setitimer(u, emulator));
                    return;
                case 118888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, fsync(u));
                    return;
                case 220: {
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, clone(emulator));
                    return;
                }
                case 160:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, uname(emulator));
                    return;
                case 135:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, sigprocmask(emulator));
                    return;
                case 132888:
                    syscall = "getpgid";
                    break;
                case 136888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, personality(u));
                    return;
                case 140888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, llseek(u, emulator));
                    return;
                case 142888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, newselect(u, emulator));
                    return;
                case 32:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, flock(emulator));
                    return;
                case 146888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, writev(u, emulator));
                    return;
                case 162888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, nanosleep(emulator));
                    return;
                case 167:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, prctl(u, emulator));
                    return;
                case 169:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, gettimeofday(emulator));
                    return;
                case 168888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, poll(u, emulator));
                    return;
                case 73:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, ppoll(emulator));
                    return;
                case 173:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, getppid(emulator));
                    return;
                case 183888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, getcwd(u, emulator));
                    return;
                case 186888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, sigaltstack(emulator));
                    return;
                case 195888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, stat64(emulator));
                    return;
                case 196888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, lstat(emulator));
                    return;
                case 174: // getuid
                case 175: // geteuid
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
                    return;
                case 200:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, bind(emulator));
                    return;
                case 201:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, listen(emulator));
                    return;
                case 202888: // getegid
                    u.reg_write(ArmConst.UC_ARM_REG_R0, 0);
                    return;
                case 205888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, getgroups(u, emulator));
                    return;
                case 208888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, setresuid32(u));
                    return;
                case 210888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, setresgid32(u));
                    return;
                case 214:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, brk(u, emulator));
                    return;
                case 215:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, munmap(u, emulator));
                    return;
                case 61:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, getdents64(emulator));
                    return;
                case 233:
                    syscall = "madvise";
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
                    return;
                case 25:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, fcntl(emulator));
                    return;
                case 222:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, mmap(u, emulator));
                    return;
                case 226:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, mprotect(u, emulator));
                    return;
                case 230888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, lgetxattr(u, emulator));
                    return;
                case 94:
                    exit_group(u);
                    return;
                case 113:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, clock_gettime(emulator));
                    return;
                case 117:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, ptrace(emulator));
                    return;
                case 266888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, statfs(emulator));
                    return;
                case 131:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, tgkill(emulator));
                    return;
                case 198:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, socket(emulator));
                    return;
                case 203:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, connect(emulator));
                    return;
                case 204:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, getsockname(emulator));
                    return;
                case 242:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, accept4(emulator));
                    return;
                case 205:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, getpeername(emulator));
                    return;
                case 206:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, sendto(emulator));
                    return;
                case 207:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, recvfrom(u, emulator));
                    return;
                case 293888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, shutdown(u, emulator));
                    return;
                case 208:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, setsockopt(emulator));
                    return;
                case 209:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, getsockopt(emulator));
                    return;
                case 323888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, mkdirat(u, emulator));
                    return;
                case 79:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, fstatat64(emulator));
                    return;
                case 48:
                    u.reg_write(Arm64Const.UC_ARM64_REG_X0, faccessat(emulator));
                    return;
                case 0xf0002888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, cacheflush(u, emulator));
                    return;
                case 0xf0005888:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, set_tls(u, emulator));
                    return;
            }
        } catch (StopEmulatorException e) {
            u.emu_stop();
            return;
        } catch (UnsupportedOperationException e) {
            exception = e;
        } catch (Throwable e) {
            u.emu_stop();
            exception = e;
        }

        if (exception == null && handleUnknownSyscall(emulator, NR)) {
            return;
        }

        log.warn("handleInterrupt intno=" + intno + ", NR=" + NR + ", svcNumber=0x" + Integer.toHexString(svcNumber) + ", PC=" + pc + ", LR=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR) + ", syscall=" + syscall, exception);

        if (exception instanceof UnicornException) {
            throw (UnicornException) exception;
        }
    }

    private long clone(Emulator<AndroidFileIO> emulator) {
        Arm64RegisterContext context = emulator.getContext();
        Pointer child_stack = context.getPointerArg(1);
        if (child_stack == null &&
                context.getPointerArg(2) == null) {
            // http://androidxref.com/6.0.1_r10/xref/bionic/libc/bionic/fork.cpp#47
            return fork(emulator); // vfork
        }

        long fn = context.getXLong(5);
        long arg = context.getXLong(6);
        if (child_stack != null && child_stack.getLong(-8) == fn && child_stack.getLong(-16) == arg) {
            // http://androidxref.com/6.0.1_r10/xref/bionic/libc/arch-arm/bionic/__bionic_clone.S#49
            return bionic_clone(emulator);
        } else {
            return pthread_clone(emulator);
        }
    }

    private int pthread_clone(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int flags = context.getIntArg(0);
        Pointer child_stack = context.getPointerArg(1);
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
        int threadId = ++this.threadId;

        Pointer fn = child_stack.getPointer(0);
        child_stack = child_stack.share(4);
        Pointer arg = child_stack.getPointer(0);
        child_stack = child_stack.share(4);

        log.info("pthread_clone child_stack=" + child_stack + ", thread_id=" + threadId + ", fn=" + fn + ", arg=" + arg + ", flags=" + list);
        threadMap.put(threadId, new LinuxThread(child_stack, fn, arg));
        lastThread = threadId;
        return threadId;
    }

    private int fsync(Unicorn u) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("fsync fd=" + fd);
        }
        return 0;
    }

    private int unlink(Emulator<?> emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        String path = FilenameUtils.normalize(pathname.getString(0));
        log.info("unlink path=" + path);
        return 0;
    }

    private int pipe(Emulator<?> emulator) {
        Pointer pipefd = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        if (log.isDebugEnabled()) {
            int readfd = pipefd.getInt(0);
            int writefd = pipefd.getInt(4);
            log.debug("pipe readfd=" + readfd + ", writefd=" + writefd);
        }
        emulator.getMemory().setErrno(UnixEmulator.EFAULT);
        return -1;
    }

    private int sigaltstack(Emulator<?> emulator) {
        Pointer ss = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer old_ss = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        if (log.isDebugEnabled()) {
            log.debug("sigaltstack ss=" + ss + ", old_ss=" + old_ss);
        }
        return 0;
    }

    private int set_tls(Unicorn u, Emulator<?> emulator) {
        UnicornPointer tls = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        if (log.isDebugEnabled()) {
            log.debug("set_tls: " + tls);
        }
        u.reg_write(UC_ARM_REG_C13_C0_3, tls.peer);
        return 0;
    }

    private int cacheflush(Unicorn u, Emulator<?> emulator) {
        Pointer begin = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer end = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int cache = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("cacheflush begin=" + begin + ", end=" + end + ", cache=" + cache);
        }
        return 0;
    }

    protected long fork(Emulator<?> emulator) {
        log.debug("fork");
        emulator.getMemory().setErrno(UnixEmulator.ENOSYS);
        return -1;
    }

    private int tgkill(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int tgid = context.getIntArg(0);
        int tid = context.getIntArg(1);
        int sig = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("tgkill tgid=" + tgid + ", tid=" + tid + ", sig=" + sig);
        }
        return 0;
    }

    private int threadId;

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
        Pointer fn = context.getPointerArg(5);
        Pointer arg = context.getPointerArg(6);
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
            log.debug("bionic_clone child_stack=" + child_stack + ", pid=" + pid + ", tls=" + tls + ", ctid=" + ctid + ", fn=" + fn + ", arg=" + arg + ", flags=" + list);
        }
        emulator.getMemory().setErrno(UnixEmulator.EAGAIN);
        throw new AbstractMethodError();
    }

    private int flock(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int operation = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("flock fd=" + fd + ", operation=" + operation);
        }
        return 0;
    }

    private int fchmod(Unicorn u) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int mode = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("fchmod fd=" + fd + ", mode=" + mode);
        }
        return 0;
    }

    private int llseek(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        long offset = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).longValue();
        Pointer result = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        int whence = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("llseek fd=" + fd + ", offset=" + offset + ", result=" + result + ", whence=" + whence);
        }

        FileIO io = fdMap.get(fd);
        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        } else {
            return io.llseek(offset, result, whence);
        }
    }

    private int access(Unicorn u, Emulator<AndroidFileIO> emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int mode = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        String path = pathname.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("access pathname=" + path + ", mode=" + mode);
        }
        int ret = faccessat(emulator, path);
        if (ret == -1) {
            log.info("access pathname=" + path + ", mode=" + mode);
        }
        return ret;
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
        log.info("execve filename=" + filename.getString(0) + ", args=" + args + ", env=" + env);
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private long persona;

    private int personality(Unicorn u) {
        long persona = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("personality persona=0x" + Long.toHexString(persona));
        }
        int old = (int) this.persona;
        if (persona != 0xffffffffL) {
            this.persona = persona;
        }
        return old;
    }

    private int shutdown(Unicorn u, Emulator<?> emulator) {
        int sockfd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int how = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("shutdown sockfd=" + sockfd + ", how=" + how);
        }

        FileIO io = fdMap.get(sockfd);
        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return io.shutdown(how);
    }

    private int dup(Unicorn u, Emulator<?> emulator) {
        int oldfd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();

        FileIO io = fdMap.get(oldfd);
        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        if (log.isDebugEnabled()) {
            log.debug("dup oldfd=" + oldfd + ", io=" + io);
        }
        FileIO _new = io.dup2();
        if (_new == null) {
            throw new UnsupportedOperationException();
        }
        int newfd = getMinFd();
        fdMap.put(newfd, (AndroidFileIO) _new);
        return newfd;
    }

    private int stat64(Emulator<AndroidFileIO> emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer statbuf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        String path = FilenameUtils.normalize(pathname.getString(0));
        if (log.isDebugEnabled()) {
            log.debug("stat64 pathname=" + path + ", statbuf=" + statbuf);
        }
        return stat64(emulator, path, statbuf);
    }

    private int lstat(Emulator<AndroidFileIO> emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer statbuf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        String path = FilenameUtils.normalize(pathname.getString(0));
        if (log.isDebugEnabled()) {
            log.debug("lstat pathname=" + path + ", statbuf=" + statbuf);
        }
        return stat64(emulator, path, statbuf);
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

        log.info("stat64 pathname=" + pathname);
        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.EACCES);
        return -1;
    }

    private int newselect(Unicorn u, Emulator<?> emulator) {
        int nfds = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer readfds = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer writefds = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        Pointer exceptfds = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        Pointer timeout = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        int size = (nfds - 1) / 8 + 1;
        if (log.isDebugEnabled()) {
            log.debug("newselect nfds=" + nfds + ", readfds=" + readfds + ", writefds=" + writefds + ", exceptfds=" + exceptfds + ", timeout=" + timeout);
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
            int count = select(nfds, writefds, readfds);
            if (count > 0) {
                return count;
            }
        }
        if (readfds != null) {
            int count = select(nfds, readfds, writefds);
            if (count > 0) {
                return count;
            }
        }
        throw new AbstractMethodError();
    }

    private int select(int nfds, Pointer checkfds, Pointer clearfds) {
        int count = 0;
        for (int i = 0; i < nfds; i++) {
            int mask = checkfds.getInt(i / 32);
            if(((mask >> i) & 1) == 1) {
                count++;
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

    private int getpeername(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        Pointer addrlen = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("getpeername sockfd=" + sockfd + ", addr=" + addr + ", addrlen=" + addrlen);
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
            Pointer pollfd = fds.share(i * 8);
            int fd = pollfd.getInt(0);
            short events = pollfd.getShort(4); // requested events
            if (log.isDebugEnabled()) {
                log.debug("ppoll fds=" + fds + ", nfds=" + nfds + ", tmo_p=" + tmo_p + ", sigmask=" + sigmask + ", fd=" + fd + ", events=" + events);
            }
            if (fd < 0) {
                pollfd.setShort(6, (short) 0);
            } else {
                short revents = 0;
                if((events & POLLOUT) != 0) {
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

    private int poll(Unicorn u, Emulator<?> emulator) {
        Pointer fds = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int nfds = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int timeout = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int count = 0;
        for (int i = 0; i < nfds; i++) {
            Pointer pollfd = fds.share(i * 8);
            int fd = pollfd.getInt(0);
            short events = pollfd.getShort(4); // requested events
            if (log.isDebugEnabled()) {
                log.debug("poll fds=" + fds + ", nfds=" + nfds + ", timeout=" + timeout + ", fd=" + fd + ", events=" + events);
            }
            if (fd < 0) {
                pollfd.setShort(6, (short) 0);
            } else {
                short revents = 0;
                if((events & POLLOUT) != 0) {
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

    private int mask = 0x12;

    private int umask(Unicorn u) {
        int mask = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("umask mask=0x" + Long.toHexString(mask));
        }
        int old = this.mask;
        this.mask = mask;
        return old;
    }

    private int setresuid32(Unicorn u) {
        int ruid = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int euid = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int suid = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("setresuid32 ruid=" + ruid + ", euid=" + euid + ", suid=" + suid);
        }
        return 0;
    }

    private int setresgid32(Unicorn u) {
        int rgid = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int egid = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int sgid = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("setresgid32 rgid=" + rgid + ", egid=" + egid + ", sgid=" + sgid);
        }
        return 0;
    }

    private int mkdir(Unicorn u, Emulator<?> emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int mode = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("mkdir pathname=" + pathname.getString(0) + ", mode=" + mode);
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int syslog(Unicorn u, Emulator<?> emulator) {
        int type = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer bufp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int len = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("syslog type=" + type + ", bufp=" + bufp + ", len=" + len);
        }
        throw new UnsupportedOperationException();
    }

    private int sigprocmask(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int how = context.getIntArg(0);
        Pointer set = context.getPointerArg(1);
        Pointer oldset = context.getPointerArg(2);
        return sigprocmask(emulator, how, set, oldset);
    }

    private int lgetxattr(Unicorn u, Emulator<?> emulator) {
        Pointer path = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer name = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer value = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("lgetxattr path=" + path.getString(0) + ", name=" + name.getString(0) + ", value=" + value + ", size=" + size);
        }
        throw new UnsupportedOperationException();
    }

    private int reboot(Unicorn u, Emulator<?> emulator) {
        int magic = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int magic2 = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int cmd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        Pointer arg = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        if (log.isDebugEnabled()) {
            log.debug("reboot magic=" + magic + ", magic2=" + magic2 + ", cmd=" + cmd + ", arg=" + arg);
        }
        emulator.getMemory().setErrno(UnixEmulator.EPERM);
        return -1;
    }

    private int nanosleep(Emulator<?> emulator) {
        Pointer req = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer rem = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int tv_sec = req.getInt(0);
        int tv_nsec = req.getInt(4);
        if (log.isDebugEnabled()) {
            log.debug("nanosleep req=" + req + ", rem=" + rem + ", tv_sec=" + tv_sec + ", tv_nsec=" + tv_nsec);
        }
        try {
            Thread.sleep(tv_sec * 1000L + tv_nsec / 1000000L);
        } catch (InterruptedException ignored) {
        }
        return 0;
    }

    private int kill(Unicorn u) {
        int pid = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int sig = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("kill pid=" + pid + ", sig=" + sig);
        }
        throw new UnsupportedOperationException();
    }

    private int setitimer(Unicorn u, Emulator<?> emulator) {
        int which = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer new_value = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer old_value = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        if (log.isDebugEnabled()) {
            log.debug("setitimer which=" + which + ", new_value=" + new_value + ", old_value=" + old_value);
        }
        return 0;
    }

    private int sigaction(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int signum = context.getIntArg(0);
        Pointer act = context.getPointerArg(1);
        Pointer oldact = context.getPointerArg(2);

        return sigaction(signum, act, oldact);
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
            log.debug("pselect6 nfds=" + nfds + ", readfds=" + readfds + ", writefds=" + writefds + ", exceptfds=" + exceptfds + ", timeout=" + timeout);
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
            int count = select(nfds, writefds, readfds);
            if (count > 0) {
                return count;
            }
        }
        if (readfds != null) {
            int count = select(nfds, readfds, writefds);
            if (count > 0) {
                return count;
            }
        }
        throw new AbstractMethodError();
    }

    private int recvfrom(Unicorn u, Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer buf = context.getPointerArg(1);
        int len = context.getIntArg(2);
        int flags = context.getIntArg(3);
        Pointer src_addr = context.getPointerArg(4);
        Pointer addrlen = context.getPointerArg(5);

        if (log.isDebugEnabled()) {
            log.debug("recvfrom sockfd=" + sockfd + ", buf=" + buf + ", flags=" + flags + ", src_addr=" + src_addr + ", addrlen=" + addrlen);
        }
        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.recvfrom(u, buf, len, flags, src_addr, addrlen);
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
            log.debug("getsockname sockfd=" + sockfd + ", addr=" + addr + ", addrlen=" + addrlen);
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
            log.debug("accept sockfd=" + sockfd + ", addr=" + addr + ", addrlen=" + addrlen + ", flags=" + flags);
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
            log.debug("getsockopt sockfd=" + sockfd + ", level=" + level + ", optname=" + optname + ", optval=" + optval + ", optlen=" + optlen);
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
            log.debug("setsockopt sockfd=" + sockfd + ", level=" + level + ", optname=" + optname + ", optval=" + optval + ", optlen=" + optlen);
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

    private int socket(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int domain = context.getIntArg(0);
        int type = context.getIntArg(1) & 0x7ffff;
        int protocol = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("socket domain=" + domain + ", type=" + type + ", protocol=" + protocol);
        }

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
        }
        throw new UnsupportedOperationException("socket domain=" + domain + ", type=" + type + ", protocol=" + protocol);
    }

    private int getgroups(Unicorn u, Emulator<?> emulator) {
        int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        if (log.isDebugEnabled()) {
            log.debug("getgroups size=" + size + ", list=" + list);
        }
        return 0;
    }

    protected int uname(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer buf = context.getPointerArg(0);
        if (log.isDebugEnabled()) {
            log.debug("uname buf=" + buf);
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
        machine.setString(0, "arm64-v8a"); /* Hardware identifier */

        Pointer domainName = machine.share(SYS_NMLN);
        domainName.setString(0, ""); /* NIS or YP domain name */

        return 0;
    }

    private int getppid(Emulator<AndroidFileIO> emulator) {
        if (log.isDebugEnabled()) {
            log.debug("getppid");
        }
        return emulator.getPid();
    }

    private int getcwd(Unicorn u, Emulator<?> emulator) {
        UnicornPointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        File workDir = emulator.getFileSystem().createWorkDir();
        String path = workDir.getAbsolutePath();
        if (log.isDebugEnabled()) {
            log.debug("getcwd buf=" + buf + ", size=" + size + ", path=" + path);
        }
        buf.setString(0, ".");
        return (int) buf.toUIntPeer();
    }

    private void exit_group(Unicorn u) {
        int status = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("exit with code: " + status, new Exception("exit_group status=" + status));
        } else {
            System.out.println("exit with code: " + status);
        }
        u.emu_stop();
    }

    private int munmap(Unicorn u, Emulator<?> emulator) {
        long timeInMillis = System.currentTimeMillis();
        long start = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).longValue();
        int length = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
        int ret = emulator.getMemory().munmap(start, length);
        if (log.isDebugEnabled()) {
            log.debug("munmap start=0x" + Long.toHexString(start) + ", length=" + length + ", ret=" + ret + ", offset=" + (System.currentTimeMillis() - timeInMillis));
        }
        return ret;
    }

    protected int statfs(Emulator<?> emulator) {
        Pointer pathPointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        String path = pathPointer.getString(0);
        log.info("statfs pathPointer=" + pathPointer + ", buf=" + buf + ", path=" + path);
        if("/sys/fs/selinux".equals(path)) {
            return -1;
        }
        throw new UnsupportedOperationException();
    }

    private static final int PR_SET_NAME = 15;
    private static final int BIONIC_PR_SET_VMA =              0x53564d41;

    private int prctl(Unicorn u, Emulator<?> emulator) {
        int option = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        long arg2 = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X1)).longValue();
        if (log.isDebugEnabled()) {
            log.debug("prctl option=0x" + Integer.toHexString(option) + ", arg2=0x" + Long.toHexString(arg2));
        }
        switch (option) {
            case PR_SET_NAME:
                Pointer threadName = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                if (log.isDebugEnabled()) {
                    log.debug("prctl set thread name: " + threadName.getString(0));
                }
                return 0;
            case BIONIC_PR_SET_VMA:
                Pointer addr = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int len = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
                Pointer pointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X4);
                if (log.isDebugEnabled()) {
                    log.debug("prctl addr=" + addr + ", len=" + len + ", pointer=" + pointer + ", name=" + pointer.getString(0));
                }
                return 0;
        }
        throw new UnsupportedOperationException("option=" + option);
    }

    private static final int CLOCK_REALTIME = 0;
    private static final int CLOCK_MONOTONIC = 1;
    private static final int CLOCK_MONOTONIC_RAW = 4;
    private static final int CLOCK_MONOTONIC_COARSE = 6;
    private static final int CLOCK_BOOTTIME = 7;

    private long nanoTime = System.nanoTime();

    private int clock_gettime(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int clk_id = context.getIntArg(0);
        Pointer tp = context.getPointerArg(1);
        long offset = clk_id == CLOCK_REALTIME ? System.currentTimeMillis() * 1000000L : System.nanoTime() - nanoTime;
        long tv_sec = offset / 1000000000L;
        long tv_nsec = offset % 1000000000L;
        if (log.isDebugEnabled()) {
            log.debug("clock_gettime clk_id=" + clk_id + ", tp=" + tp + ", offset=" + offset + ", tv_sec=" + tv_sec + ", tv_nsec=" + tv_nsec);
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
        throw new UnsupportedOperationException("clk_id=" + clk_id);
    }

    protected long ptrace(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int request = context.getIntArg(0);
        int pid = context.getIntArg(1);
        Pointer addr = context.getPointerArg(2);
        Pointer data = context.getPointerArg(3);
        log.info("ptrace request=0x" + Integer.toHexString(request) + ", pid=" + pid + ", addr=" + addr + ", data=" + data);
        return 0;
    }

    private int fcntl(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int cmd = context.getIntArg(1);
        int arg = context.getIntArg(2);
        return fcntl(emulator, fd, cmd, arg);
    }

    private int writev(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer iov = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int iovcnt = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        if (log.isDebugEnabled()) {
            for (int i = 0; i < iovcnt; i++) {
                Pointer iov_base = iov.getPointer(i * 8);
                int iov_len = iov.getInt(i * 8 + 4);
                byte[] data = iov_base.getByteArray(0, iov_len);
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
            Pointer iov_base = iov.getPointer(i * 8);
            int iov_len = iov.getInt(i * 8 + 4);
            byte[] data = iov_base.getByteArray(0, iov_len);
            count += file.write(data);
        }
        return count;
    }

    private static final int FUTEX_WAIT = 0;
    private static final int FUTEX_WAKE = 1;

    private int futex(Unicorn u, Emulator<?> emulator) {
        Pointer uaddr = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
        int futex_op = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
        int val = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
        int old = uaddr.getInt(0);
        if (log.isDebugEnabled()) {
            log.debug("futex uaddr=" + uaddr + ", _futexop=" + futex_op + ", op=" + (futex_op & 0x7f) + ", val=" + val + ", old=" + old);
        }

        switch (futex_op & 0x7f) {
            case FUTEX_WAIT:
                if (old != val) {
                    throw new IllegalStateException("old=" + old + ", val=" + val);
                }
                Pointer timeout = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                int mytype = val & 0xc000;
                int shared = val & 0x2000;
                if (log.isDebugEnabled()) {
                    log.debug("futex FUTEX_WAIT mytype=" + mytype + ", shared=" + shared + ", timeout=" + timeout + ", test=" + (mytype | shared));
                }
                uaddr.setInt(0, mytype | shared);
                return 0;
            case FUTEX_WAKE:
                return 0;
            default:
                throw new AbstractMethodError();
        }
    }

    private long brk(Unicorn u, Emulator<?> emulator) {
        long address = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).longValue();
        if (log.isDebugEnabled()) {
            log.debug("brk address=0x" + Long.toHexString(address));
        }
        return emulator.getMemory().brk(address);
    }

    private int mprotect(Unicorn u, Emulator<?> emulator) {
        long address = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).longValue();
        int length = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
        int prot = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
        long alignedAddress = address / ARMEmulator.PAGE_ALIGN * ARMEmulator.PAGE_ALIGN; // >> 12 << 12;
        long offset = address - alignedAddress;

        long alignedLength = ARM.alignSize(length + offset, emulator.getPageAlign());
        if (log.isDebugEnabled()) {
            log.debug("mprotect address=0x" + Long.toHexString(address) + ", alignedAddress=0x" + Long.toHexString(alignedAddress) + ", offset=" + offset + ", length=" + length + ", alignedLength=" + alignedLength + ", prot=0x" + Integer.toHexString(prot));
        }
        return emulator.getMemory().mprotect(alignedAddress, (int) alignedLength, prot);
    }

    private static final int MMAP2_SHIFT = 12;

    private long mmap(Unicorn u, Emulator<?> emulator) {
        long start = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).longValue();
        int length = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
        int prot = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
        int flags = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
        int fd = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X4)).intValue();
        int offset = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X5)).intValue() << MMAP2_SHIFT;

        boolean warning = length >= 0x10000000;
        if (log.isDebugEnabled() || warning) {
            String msg = "mmap start=0x" + Long.toHexString(start) + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset;
            if (warning) {
                log.warn(msg);
            } else {
                log.debug(msg);
            }
        }
        return emulator.getMemory().mmap2(start, length, prot, flags, fd, offset);
    }

    private int gettimeofday(Emulator<?> emulator) {
        Pointer tv = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
        Pointer tz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
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
            log.debug("faccessat dirfd=" + dirfd + ", pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode));
        }
        int ret = faccessat(emulator, pathname);
        if (ret == -1) {
            log.info("faccessat failed dirfd=" + dirfd + ", pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode));
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
        String path = FilenameUtils.normalize(pathname.getString(0));
        if (log.isDebugEnabled()) {
            log.debug("fstatat64 dirfd=" + dirfd + ", pathname=" + path + ", statbuf=" + statbuf + ", flags=" + flags);
        }
        if (path.startsWith("/")) {
            return stat64(emulator, path, statbuf);
        } else {
            if (dirfd != IO.AT_FDCWD) {
                throw new UnicornException("dirfd=" + dirfd);
            }

            log.warn("fstatat64 dirfd=" + dirfd + ", pathname=" + path + ", statbuf=" + statbuf + ", flags=" + flags);
            emulator.getMemory().setErrno(UnixEmulator.EACCES);
            return -1;
        }
    }

    private int mkdirat(Unicorn u, Emulator<?> emulator) {
        int dirfd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer pathname_p = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int mode = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        String pathname = pathname_p.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("mkdirat dirfd=" + dirfd + ", pathname=" + pathname + ", mode=" + Integer.toHexString(mode));
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int openat(Unicorn u, Emulator<AndroidFileIO> emulator) {
        int dirfd = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        Pointer pathname_p = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        int oflags = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
        int mode = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
        String pathname = pathname_p.getString(0);
        String msg = "openat dirfd=" + dirfd + ", pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode);
        if (log.isDebugEnabled()) {
            log.debug(msg);
        }
        if (pathname.startsWith("/")) {
            int fd = open(emulator, pathname, oflags);
            if (fd == -1) {
                log.info(msg);
            }
            return fd;
        } else {
            if (dirfd != IO.AT_FDCWD) {
                throw new UnicornException();
            }

            log.warn(msg);
            emulator.getMemory().setErrno(UnixEmulator.EACCES);
            return -1;
        }
    }

    private int open(Unicorn u, Emulator<AndroidFileIO> emulator) {
        Pointer pathname_p = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int oflags = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int mode = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        String pathname = pathname_p.getString(0);
        String msg = "open pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode);
        if (log.isDebugEnabled()) {
            log.debug(msg);
        }
        int fd = open(emulator, pathname, oflags);
        if (fd == -1) {
            log.info(msg);
        }
        return fd;
    }

    private int ftruncate(Unicorn u) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int length = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("ftruncate fd=" + fd + ", length=" + length);
        }
        FileIO file = fdMap.get(fd);
        if (file == null) {
            throw new UnsupportedOperationException();
        }
        return file.ftruncate(length);
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
            log.debug("lseek fd=" + fd + ", offset=" + offset + ", whence=" + whence + ", pos=" + pos);
        }
        return pos;
    }

    private int close(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("close fd=" + fd);
        }

        FileIO file = fdMap.remove(fd);
        if (file != null) {
            file.close();
            return 0;
        } else {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
    }

    private int getdents64(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        UnicornPointer dirp = context.getPointerArg(1);
        int size = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("getdents64 fd=" + fd + ", dirp=" + dirp + ", size=" + size);
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
            throw new UnicornException();
        }
        return readlink(emulator, path, buf, bufSize);
    }

    private int fstat(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        Pointer stat = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        return fstat(emulator, fd, stat);
    }

    protected int fstat(Emulator<?> emulator, int fd, Pointer stat) {
        AndroidFileIO file = fdMap.get(fd);
        if (file == null) {
            if (log.isDebugEnabled()) {
                log.debug("fstat fd=" + fd + ", stat=" + stat + ", errno=" + UnixEmulator.EBADF);
            }

            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        if (log.isDebugEnabled()) {
            log.debug("fstat file=" + file + ", stat=" + stat + ", from=" + emulator.getContext().getLRPointer());
        }
        return file.fstat(emulator, new Stat64(stat));
    }

    private int ioctl(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        long request = context.getLongArg(1);
        long argp = context.getLongArg(2);
        if (log.isDebugEnabled()) {
            log.debug("ioctl fd=" + fd + ", request=0x" + Long.toHexString(request) + ", argp=0x" + Long.toHexString(argp));
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

    private int read(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X0)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        int count = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
        return read(emulator, fd, buffer, count);
    }

    private int dup3(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int oldfd = context.getIntArg(0);
        int newfd = context.getIntArg(1);
        int flags = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("dup3 oldfd=" + oldfd + ", newfd=" + newfd + ", flags=0x" + Integer.toHexString(flags));
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
