package com.github.unidbg.linux;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.StopEmulatorException;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.file.*;
import com.github.unidbg.linux.struct.Stat32;
import com.github.unidbg.linux.struct.SysInfo32;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * http://androidxref.com/6.0.0_r5/xref/bionic/libc/kernel/uapi/asm-arm/asm/unistd.h
 */
public class ARM32SyscallHandler extends AndroidSyscallHandler {

    private static final Log log = LogFactory.getLog(ARM32SyscallHandler.class);

    private final SvcMemory svcMemory;

    public ARM32SyscallHandler(SvcMemory svcMemory) {
        super();

        this.svcMemory = svcMemory;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void hook(Backend backend, int intno, int swi, Object user) {
        Emulator<AndroidFileIO> emulator = (Emulator<AndroidFileIO>) user;
        UnidbgPointer pc = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
        final int bkpt;
        if (ARM.isThumb(backend)) {
            bkpt = pc.getShort(0) & 0xff;
        } else {
            int instruction = pc.getInt(0);
            bkpt = (instruction & 0xf) | ((instruction >> 8) & 0xfff) << 4;
        }

        if (intno == ARMEmulator.EXCP_BKPT) { // bkpt
            createBreaker(emulator).brk(pc, bkpt);
            return;
        }

        if (intno != ARMEmulator.EXCP_SWI) {
            throw new BackendException("intno=" + intno);
        }

        int NR = backend.reg_read(ArmConst.UC_ARM_REG_R7).intValue();
        String syscall = null;
        Throwable exception = null;
        try {
            if (swi == 0 && NR == 0 && (backend.reg_read(ArmConst.UC_ARM_REG_R5).intValue()) == Svc.CALLBACK_SYSCALL_NUMBER) { // callback
                int number = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handleCallback(emulator);
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi);
            }
            if (swi != 0) {
                Svc svc = svcMemory.getSvc(swi);
                if (svc != null) {
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, (int) svc.handle(emulator));
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi);
            }

            if (log.isDebugEnabled()) {
                ARM.showThumbRegs(emulator);
            }

            if (handleSyscall(emulator, NR)) {
                return;
            }

            switch (NR) {
                case 1:
                    int status = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
                    System.out.println("exit status=" + status);
                    backend.emu_stop();
                    return;
                case 2:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fork(emulator));
                    return;
                case 3:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, read(emulator));
                    return;
                case 4:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, write(emulator));
                    return;
                case 5:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, open(emulator));
                    return;
                case 6:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, close(emulator));
                    return;
                case 10:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, unlink(emulator));
                    return;
                case 11:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, execve(emulator));
                    return;
                case 19:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, lseek(emulator));
                    return;
                case 26:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, ptrace(emulator));
                    return;
                case  20: // getpid
                case 224: // gettid
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, emulator.getPid());
                    return;
                case 33:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, access(emulator));
                    return;
                case 36: // sync: causes all pending modifications to filesystem metadata and cached file data to be written to the underlying filesystems.
                    return;
                case 37:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, kill(emulator));
                    return;
                case 38:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, rename(emulator));
                    return;
                case 39:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mkdir(emulator));
                    return;
                case 41:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, dup(emulator));
                    return;
                case 42:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, pipe(emulator));
                    return;
                case 45:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, brk(emulator));
                    return;
                case 54:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, ioctl(emulator));
                    return;
                case 57:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, setpgid(emulator));
                    return;
                case 60:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, umask(emulator));
                    return;
                case 63:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, dup2(backend, emulator));
                    return;
                case 64:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getppid(emulator));
                    return;
                case 67:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sigaction(backend, emulator));
                    return;
                case 78:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, gettimeofday(emulator));
                    return;
                case 85:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, readlink(emulator));
                    return;
                case 88:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, reboot(backend, emulator));
                    return;
                case 91:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, munmap(backend, emulator));
                    return;
                case 93:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, ftruncate(backend));
                    return;
                case 94:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fchmod(backend));
                    return;
                case 103:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, syslog(backend, emulator));
                    return;
                case 104:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, setitimer(emulator));
                    return;
                case 116:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sysinfo(emulator));
                    return;
                case 118:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fsync(backend));
                    return;
                case 120:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, clone(backend, emulator));
                    return;
                case 122:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, uname(emulator));
                    return;
                case 125:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mprotect(backend, emulator));
                    return;
                case 126:
                case 175:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sigprocmask(backend, emulator));
                    return;
                case 132:
                    syscall = "getpgid";
                    break;
                case 136:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, personality(backend));
                    return;
                case 140:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, llseek(backend, emulator));
                    return;
                case 142:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, newselect(backend, emulator));
                    return;
                case 143:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, flock(backend));
                    return;
                case 146:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, writev(backend, emulator));
                    return;
                case 147:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getsid(emulator));
                    return;
                case 162:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, nanosleep(emulator));
                    return;
                case 163:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mremap(emulator));
                    return;
                case 168:
                case 336:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, poll(backend, emulator));
                    return;
                case 172:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, prctl(backend, emulator));
                    return;
                case 183:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getcwd(backend, emulator));
                    return;
                case 186:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sigaltstack(emulator));
                    return;
                case 192:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mmap2(backend, emulator));
                    return;
                case 194:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, ftruncate(backend));
                    return;
                case 195:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, stat64(emulator));
                    return;
                case 196:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, lstat(emulator));
                    return;
                case 197:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fstat(backend, emulator));
                    return;
                case 199: // getuid
                case 200: // getgid
                case 201: // geteuid
                case 202: // getegid
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, 0);
                    return;
                case 205:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getgroups(backend, emulator));
                    return;
                case 208:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, setresuid32(backend));
                    return;
                case 210:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, setresgid32(backend));
                    return;
                case 214:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, setgid32(emulator));
                    return;
                case 217:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getdents64(emulator));
                    return;
                case 220:
                    syscall = "madvise";
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, 0);
                    return;
                case 221:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fcntl(backend, emulator));
                    return;
                case 230:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, lgetxattr(backend, emulator));
                    return;
                case 238:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, tkill(emulator));
                    return;
                case 240:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, futex(emulator));
                    return;
                case 248:
                    exit_group(emulator);
                    return;
                case 263:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, clock_gettime(backend, emulator));
                    return;
                case 266: {
                    RegisterContext context = emulator.getContext();
                    Pointer pathPointer = context.getPointerArg(0);
                    int size = context.getIntArg(1);
                    Pointer buf = context.getPointerArg(2).setSize(size);
                    String path = pathPointer.getString(0);
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, (int) statfs64(emulator, path, buf));
                    return;
                }
                case 268:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, tgkill(backend));
                    return;
                case 269:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, utimes(emulator));
                    return;
                case 281:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, socket(backend, emulator));
                    return;
                case 282:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, bind(emulator));
                    return;
                case 283:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, connect(backend, emulator));
                    return;
                case 284:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, listen(emulator));
                    return;
                case 285:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, accept(emulator));
                    return;
                case 286:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getsockname(backend, emulator));
                    return;
                case 287:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getpeername(backend, emulator));
                    return;
                case 290:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sendto(backend, emulator));
                    return;
                case 292:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, recvfrom(emulator));
                    return;
                case 293:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, shutdown(backend, emulator));
                    return;
                case 294:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, setsockopt(backend, emulator));
                    return;
                case 295:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getsockopt(backend, emulator));
                    return;
                case 322:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, openat(backend, emulator));
                    return;
                case 323:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mkdirat(backend, emulator));
                    return;
                case 327:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fstatat64(backend, emulator));
                    return;
                case 328:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, unlinkat(emulator));
                    return;
                case 332:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, readlinkat(emulator));
                    return;
                case 329:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, renameat(emulator));
                    return;
                case 334:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, faccessat(backend, emulator));
                    return;
                case 335:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, pselect6(emulator));
                    return;
                case 345:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getcpu(emulator));
                    return;
                case 348:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, utimensat(backend, emulator));
                    return;
                case 358:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, dup3(emulator));
                    return;
                case 366:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, accept4(emulator));
                    return;
                case 384:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getrandom(emulator));
                    return;
                case 0xf0002:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, cacheflush(backend, emulator));
                    return;
                case 0xf0005:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, set_tls(backend, emulator));
                    return;
            }
        } catch (StopEmulatorException e) {
            backend.emu_stop();
            return;
        } catch (Throwable e) {
            backend.emu_stop();
            exception = e;
        }

        if (exception == null && handleUnknownSyscall(emulator, NR)) {
            return;
        }

        log.warn("handleInterrupt intno=" + intno + ", NR=" + NR + ", svcNumber=0x" + Integer.toHexString(swi) + ", PC=" + pc + ", syscall=" + syscall, exception);

        if (exception instanceof RuntimeException) {
            throw (RuntimeException) exception;
        }
    }

    private int getrandom(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer buf = context.getPointerArg(0);
        int bufSize = context.getIntArg(1);
        int flags = context.getIntArg(2);
        return getrandom(buf, bufSize, flags);
    }

    private int clone(Backend backend, Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer child_stack = context.getPointerArg(1);
        if (child_stack == null &&
                context.getPointerArg(2) == null) {
            // http://androidxref.com/6.0.1_r10/xref/bionic/libc/bionic/fork.cpp#47
            return fork(emulator); // vfork
        }

        int fn = context.getR5Int();
        int arg = context.getR6Int();
        if (child_stack != null && child_stack.getInt(-4) == fn && child_stack.getInt(-8) == arg) {
            // http://androidxref.com/6.0.1_r10/xref/bionic/libc/arch-arm/bionic/__bionic_clone.S#49
            return bionic_clone(backend, emulator);
        } else {
            return pthread_clone(backend, emulator);
        }
    }

    private int tkill(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int tid = context.getIntArg(0);
        int sig = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("tkill tid=" + tid + ", sig=" + sig);
        }
        return 0;
    }

    private int setpgid(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        int pgid = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("setpgid pid=" + pid + ", pgid=" + pgid);
        }
        return 0;
    }

    private int getsid(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("getsid pid=" + pid);
        }
        return emulator.getPid();
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

    private int readlink(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pathname = context.getPointerArg(0);
        Pointer buf = context.getPointerArg(1);
        int bufSize = context.getIntArg(2);
        String path = pathname.getString(0);
        return readlink(emulator, path, buf, bufSize);
    }

    private int getppid(Emulator<?> emulator) {
        if (log.isDebugEnabled()) {
            log.debug("getppid");
        }
        return emulator.getPid();
    }

    private int getcpu(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer cpu = context.getR0Pointer();
        Pointer node = context.getR1Pointer();
        Pointer tcache = context.getR2Pointer();
        if (log.isDebugEnabled()) {
            log.debug("getcpu cpu=" + cpu + ", node=" + node + ", tcache=" + tcache);
        }
        if (cpu != null) {
            cpu.setInt(0, 0);
        }
        if (node != null) {
            node.setInt(0, 0);
        }
        return 0;
    }

    private int sysinfo(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer info = context.getR0Pointer();
        if (log.isDebugEnabled()) {
            log.debug("sysinfo info=" + info);
        }
        SysInfo32 sysInfo32 = new SysInfo32(info);
        sysInfo32.pack();
        return 0;
    }

    private static final int MREMAP_MAYMOVE = 1;

    private int mremap(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        UnidbgPointer old_address = context.getR0Pointer();
        int old_size = context.getR1Int();
        int new_size = context.getR2Int();
        int flags = context.getR3Int();
        Pointer new_address = context.getR4Pointer();
        if (log.isDebugEnabled()) {
            log.debug("mremap old_address=" + old_address + ", old_size=" + old_size + ", new_size=" + new_size + ", flags=" + flags + ", new_address=" + new_address);
        }
        if (old_size == 0) {
            throw new BackendException("old_size is zero");
        }
        if ((flags & MREMAP_MAYMOVE) == 0) {
            throw new BackendException("flags=" + flags);
        }

        Memory memory = emulator.getMemory();
        for (MemoryMap map : memory.getMemoryMap()) {
            if (map.base == old_address.toUIntPeer() && map.size == old_size) {
                byte[] data = new byte[old_size];
                old_address.read(0, data, 0, data.length);
                memory.munmap(map.base, (int) map.size);
                long address = emulator.getMemory().mmap2(0, new_size, map.prot, AndroidElfLoader.MAP_ANONYMOUS, 0, 0);
                UnidbgPointer pointer = UnidbgPointer.pointer(emulator, address);
                assert pointer != null;
                pointer.write(0, data, 0, data.length);
                return (int) pointer.toUIntPeer();
            }
        }
        throw new BackendException();
    }

    protected int ptrace(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int request = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int pid = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        Pointer addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        Pointer data = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        log.info("ptrace request=0x" + Integer.toHexString(request) + ", pid=" + pid + ", addr=" + addr + ", data=" + data);
        return 0;
    }

    private int utimes(Emulator<?> emulator) {
        Pointer filename = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer times = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        if (log.isDebugEnabled()) {
            log.debug("utimes filename=" + filename.getString(0) + ", times=" + times);
        }
        return 0;
    }

    private int utimensat(Backend backend, Emulator<?> emulator) {
        int dirfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer pathname = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer times = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        if (log.isDebugEnabled()) {
            log.debug("utimensat dirfd=" + dirfd + ", pathname=" + pathname.getString(0) + ", times=" + times + ", flags=" + flags);
        }
        return 0;
    }

    private int fsync(Backend backend) {
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        if (log.isDebugEnabled()) {
            log.debug("fsync fd=" + fd);
        }
        return 0;
    }

    private int rename(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer oldpath = context.getR0Pointer();
        Pointer newpath = context.getR1Pointer();
        log.info("rename oldpath=" + oldpath.getString(0) + ", newpath=" + newpath.getString(0));
        return 0;
    }

    private int renameat(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        int olddirfd = context.getR0Int();
        Pointer oldpath = context.getR1Pointer();
        int newdirfd = context.getR2Int();
        Pointer newpath = context.getR3Pointer();
        log.info("renameat olddirfd=" + olddirfd + ", oldpath=" + oldpath.getString(0) + ", newdirfd=" + newdirfd + ", newpath=" + newpath.getString(0));
        return 0;
    }

    private int unlinkat(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        int dirfd = context.getR0Int();
        Pointer pathname = context.getR1Pointer();
        int flags = context.getR2Int();
        log.info("unlinkat dirfd=" + dirfd + ", pathname=" + pathname.getString(0) + ", flags=" + flags);
        return 0;
    }

    private int unlink(Emulator<?> emulator) {
        Pointer pathname = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        String path = FilenameUtils.normalize(pathname.getString(0), true);
        log.info("unlink path=" + path);
        return 0;
    }

    private int pipe(Emulator<?> emulator) {
        Pointer pipefd = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        if (log.isDebugEnabled()) {
            int readfd = pipefd.getInt(0);
            int writefd = pipefd.getInt(4);
            log.debug("pipe readfd=" + readfd + ", writefd=" + writefd);
        }
        emulator.getMemory().setErrno(UnixEmulator.EFAULT);
        return -1;
    }

    private int sigaltstack(Emulator<?> emulator) {
        Pointer ss = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer old_ss = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        if (log.isDebugEnabled()) {
            log.debug("sigaltstack ss=" + ss + ", old_ss=" + old_ss);
        }
        return 0;
    }

    private int set_tls(Backend backend, Emulator<?> emulator) {
        UnidbgPointer tls = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        if (log.isDebugEnabled()) {
            log.debug("set_tls: " + tls);
        }
        backend.reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tls.peer);
        return 0;
    }

    private int cacheflush(Backend backend, Emulator<?> emulator) {
        Pointer begin = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer end = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int cache = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        if (log.isDebugEnabled()) {
            log.debug("cacheflush begin=" + begin + ", end=" + end + ", cache=" + cache);
        }
        return 0;
    }

    protected int fork(Emulator<?> emulator) {
        log.info("fork");
        emulator.getMemory().setErrno(UnixEmulator.ENOSYS);
        return -1;
    }

    private int tgkill(Backend backend) {
        int tgid = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int tid = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int sig = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
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

    private int pthread_clone(Backend backend, Emulator<?> emulator) {
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer child_stack = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
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

    private int bionic_clone(Backend backend, Emulator<?> emulator) {
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer child_stack = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer pid = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        Pointer tls = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        Pointer ctid = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        Pointer fn = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R5);
        Pointer arg = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R6);
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
            log.debug("bionic_clone child_stack=" + child_stack + ", thread_id=" + threadId + ", pid=" + pid + ", tls=" + tls + ", ctid=" + ctid + ", fn=" + fn + ", arg=" + arg + ", flags=" + list);
        }
        emulator.getMemory().setErrno(UnixEmulator.EAGAIN);
        throw new AbstractMethodError();
    }

    private int flock(Backend backend) {
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int operation = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        if (log.isDebugEnabled()) {
            log.debug("flock fd=" + fd + ", operation=" + operation);
        }
        return 0;
    }

    private int fchmod(Backend backend) {
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int mode = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        if (log.isDebugEnabled()) {
            log.debug("fchmod fd=" + fd + ", mode=" + mode);
        }
        return 0;
    }

    private int llseek(Backend backend, Emulator<?> emulator) {
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        long offset_high = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue() & 0xffffffffL;
        long offset_low = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue() & 0xffffffffL;
        long offset = (offset_high<<32) | offset_low;
        Pointer result = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        int whence = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
        if (log.isDebugEnabled()) {
            log.debug("llseek fd=" + fd + ", offset_high=" + offset_high + ", offset_low=" + offset_low + ", result=" + result + ", whence=" + whence);
        }

        FileIO io = fdMap.get(fd);
        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        } else {
            return io.llseek(offset, result, whence);
        }
    }

    private int access(Emulator<AndroidFileIO> emulator) {
        Backend backend = emulator.getBackend();
        Pointer pathname = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int mode = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        if (pathname == null) {
            emulator.getMemory().setErrno(UnixEmulator.EINVAL);
            return -1;
        }

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
        Pointer filename = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer argv = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer envp = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        assert filename != null;
        List<String> args = new ArrayList<>();
        Pointer pointer;
        while ((pointer = argv.getPointer(0)) != null) {
            args.add(pointer.getString(0));
            argv = argv.share(4);
        }
        List<String> env = new ArrayList<>();
        while ((pointer = envp.getPointer(0)) != null) {
            env.add(pointer.getString(0));
            envp = envp.share(4);
        }
        log.info("execve filename=" + filename.getString(0) + ", args=" + args + ", env=" + env);
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private long persona;

    private int personality(Backend backend) {
        long persona = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("personality persona=0x" + Long.toHexString(persona));
        }
        int old = (int) this.persona;
        if (persona != 0xffffffffL) {
            this.persona = persona;
        }
        return old;
    }

    private int shutdown(Backend backend, Emulator<?> emulator) {
        int sockfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int how = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
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

    private int dup(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int oldfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();

        FileIO io = fdMap.get(oldfd);
        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        if (log.isDebugEnabled()) {
            log.debug("dup oldfd=" + oldfd + ", io=" + io);
        }
        AndroidFileIO _new = (AndroidFileIO) io.dup2();
        if (_new == null) {
            throw new UnsupportedOperationException();
        }
        int newfd = getMinFd();
        fdMap.put(newfd, _new);
        return newfd;
    }

    private int stat64(Emulator<AndroidFileIO> emulator) {
        Pointer pathname = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer statbuf = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        String path = FilenameUtils.normalize(pathname.getString(0), true);
        if (log.isDebugEnabled()) {
            log.debug("stat64 pathname=" + path + ", statbuf=" + statbuf);
        }
        return stat64(emulator, path, statbuf);
    }

    private int lstat(Emulator<AndroidFileIO> emulator) {
        Pointer pathname = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer statbuf = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        String path = FilenameUtils.normalize(pathname.getString(0), true);
        if (log.isDebugEnabled()) {
            log.debug("lstat pathname=" + path + ", statbuf=" + statbuf);
        }
        return stat64(emulator, path, statbuf);
    }

    protected int stat64(Emulator<AndroidFileIO> emulator, String pathname, Pointer statbuf) {
        FileResult<AndroidFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            return result.io.fstat(emulator, new Stat32(statbuf));
        }

        log.info("stat64 pathname=" + pathname + ", LR=" + emulator.getContext().getLRPointer());
        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.ENOENT);
        return -1;
    }

    private int newselect(Backend backend, Emulator<?> emulator) {
        int nfds = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer readfds = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer writefds = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        Pointer exceptfds = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        Pointer timeout = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
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

    private int pselect6(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        int nfds = context.getIntArg(0);
        Pointer readfds = context.getPointerArg(1);
        Pointer writefds = context.getPointerArg(2);
        Pointer exceptfds = context.getPointerArg(3);
        Pointer timeout = context.getR4Pointer();
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

    private int getpeername(Backend backend, Emulator<?> emulator) {
        int sockfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer addrlen = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
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

    private int poll(Backend backend, Emulator<?> emulator) {
        Pointer fds = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int nfds = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int timeout = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int count = 0;
        for (int i = 0; i < nfds; i++) {
            Pointer pollfd = fds.share(i * 8L);
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

    private int umask(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int mask = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        if (log.isDebugEnabled()) {
            log.debug("umask mask=0x" + Long.toHexString(mask));
        }
        int old = this.mask;
        this.mask = mask;
        return old;
    }

    private int setresuid32(Backend backend) {
        int ruid = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int euid = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int suid = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        if (log.isDebugEnabled()) {
            log.debug("setresuid32 ruid=" + ruid + ", euid=" + euid + ", suid=" + suid);
        }
        return 0;
    }

    private int setgid32(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int gid = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("setgid32 gid=" + gid);
        }
        return 0;
    }

    private int setresgid32(Backend backend) {
        int rgid = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int egid = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int sgid = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        if (log.isDebugEnabled()) {
            log.debug("setresgid32 rgid=" + rgid + ", egid=" + egid + ", sgid=" + sgid);
        }
        return 0;
    }

    private int mkdir(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        Pointer pathname = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int mode = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        if (log.isDebugEnabled()) {
            log.debug("mkdir pathname=" + pathname.getString(0) + ", mode=" + mode);
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int syslog(Backend backend, Emulator<?> emulator) {
        int type = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer bufp = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int len = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        if (log.isDebugEnabled()) {
            log.debug("syslog type=" + type + ", bufp=" + bufp + ", len=" + len);
        }
        throw new UnsupportedOperationException();
    }

    private int sigprocmask(Backend backend, Emulator<?> emulator) {
        int how = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer set = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oldset = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        return sigprocmask(emulator, how, set, oldset);
    }

    private int lgetxattr(Backend backend, Emulator<?> emulator) {
        Pointer path = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer name = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer value = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        int size = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        if (log.isDebugEnabled()) {
            log.debug("lgetxattr path=" + path.getString(0) + ", name=" + name.getString(0) + ", value=" + value + ", size=" + size);
        }
        throw new UnsupportedOperationException();
    }

    private int reboot(Backend backend, Emulator<?> emulator) {
        int magic = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int magic2 = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int cmd = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        Pointer arg = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        if (log.isDebugEnabled()) {
            log.debug("reboot magic=" + magic + ", magic2=" + magic2 + ", cmd=" + cmd + ", arg=" + arg);
        }
        emulator.getMemory().setErrno(UnixEmulator.EPERM);
        return -1;
    }

    private int nanosleep(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer req = context.getR0Pointer();
        Pointer rem = context.getR1Pointer();
        int tv_sec = req.getInt(0);
        int tv_nsec = req.getInt(4);
        if (log.isDebugEnabled()) {
            log.debug("nanosleep req=" + req + ", rem=" + rem + ", tv_sec=" + tv_sec + ", tv_nsec=" + tv_nsec);
        }
        try {
            java.lang.Thread.sleep(tv_sec * 1000L + tv_nsec / 1000000L);
        } catch (InterruptedException ignored) {
        }
        return 0;
    }

    protected int kill(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        int sig = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("kill pid=" + pid + ", sig=" + sig);
        }
        throw new UnsupportedOperationException("kill pid=" + pid + ", sig=" + sig + ", LR=" + context.getLRPointer());
    }

    private int setitimer(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        int which = context.getR0Int();
        Pointer new_value = context.getR1Pointer();
        Pointer old_value = context.getR2Pointer();
        if (log.isDebugEnabled()) {
            log.debug("setitimer which=" + which + ", new_value=" + new_value + ", old_value=" + old_value);
        }
        return 0;
    }

    private int sigaction(Backend backend, Emulator<?> emulator) {
        int signum = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer act = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oldact = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);

        return sigaction(signum, act, oldact);
    }

    private int recvfrom(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int sockfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer buf = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int len = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        Pointer src_addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        Pointer addrlen = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R5);

        if (log.isDebugEnabled()) {
            log.debug("recvfrom sockfd=" + sockfd + ", buf=" + buf + ", flags=" + flags + ", src_addr=" + src_addr + ", addrlen=" + addrlen);
        }
        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.recvfrom(backend, buf, len, flags, src_addr, addrlen);
    }

    private int sendto(Backend backend, Emulator<?> emulator) {
        int sockfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer buf = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int len = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        Pointer dest_addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        int addrlen = backend.reg_read(ArmConst.UC_ARM_REG_R5).intValue();

        return sendto(emulator, sockfd, buf, len, flags, dest_addr, addrlen);
    }

    private int connect(Backend backend, Emulator<?> emulator) {
        int sockfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int addrlen = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        return connect(emulator, sockfd, addr, addrlen);
    }

    private int accept(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        Pointer addrlen = context.getPointerArg(2);
        return accept(emulator, sockfd, addr, addrlen, 0);
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

    private int listen(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        int backlog = context.getIntArg(1);
        return listen(emulator, sockfd, backlog);
    }

    private int bind(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        int addrlen = context.getIntArg(2);
        return bind(emulator, sockfd, addr, addrlen);
    }

    private int getsockname(Backend backend, Emulator<?> emulator) {
        int sockfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer addrlen = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
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

    private int getsockopt(Backend backend, Emulator<?> emulator) {
        int sockfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int level = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int optname = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        Pointer optval = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        Pointer optlen = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        if (log.isDebugEnabled()) {
            log.debug("getsockopt sockfd=" + sockfd + ", level=" + level + ", optname=" + optname + ", optval=" + optval + ", optlen=" + optlen + ", from=" + UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
        }

        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.getsockopt(level, optname, optval, optlen);
    }

    private int setsockopt(Backend backend, Emulator<?> emulator) {
        int sockfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int level = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int optname = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        Pointer optval = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        int optlen = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
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

    private int socket(Backend backend, Emulator<?> emulator) {
        int domain = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int type = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue() & 0x7ffff;
        int protocol = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
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
        log.warn("socket domain=" + domain + ", type=" + type + ", protocol=" + protocol);
        emulator.getMemory().setErrno(UnixEmulator.EAFNOSUPPORT);
        return -1;
    }

    private int getgroups(Backend backend, Emulator<?> emulator) {
        int size = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer list = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        if (log.isDebugEnabled()) {
            log.debug("getgroups size=" + size + ", list=" + list);
        }
        return 0;
    }

    protected int uname(Emulator<?> emulator) {
        Pointer buf = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        if (log.isDebugEnabled()) {
            log.debug("uname buf=" + buf);
        }

        final int SYS_NMLN = 65;

        Pointer sysname = buf.share(0);
        sysname.setString(0, "Linux");

        Pointer nodename = sysname.share(SYS_NMLN);
        nodename.setString(0, "localhost");

        Pointer release = nodename.share(SYS_NMLN);
        release.setString(0, "1.0.0-unidbg");

        Pointer version = release.share(SYS_NMLN);
        version.setString(0, "#1 SMP PREEMPT Thu Apr 19 14:36:58 CST 2018");

        Pointer machine = version.share(SYS_NMLN);
        machine.setString(0, "armv7l");

        Pointer domainname = machine.share(SYS_NMLN);
        domainname.setString(0, "localdomain");

        return 0;
    }

    private int getcwd(Backend backend, Emulator<?> emulator) {
        UnidbgPointer buf = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int size = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        File workDir = emulator.getFileSystem().createWorkDir();
        String path = workDir.getAbsolutePath();
        if (log.isDebugEnabled()) {
            log.debug("getcwd buf=" + buf + ", size=" + size + ", path=" + path);
        }
        buf.setString(0, ".");
        return (int) buf.peer;
    }

    private void exit_group(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int status = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("exit with code: " + status, new Exception("exit_group status=" + status));
        } else {
            System.out.println("exit with code: " + status);
        }
        if (LogFactory.getLog(AbstractEmulator.class).isDebugEnabled()) {
            createBreaker(emulator).debug();
        }
        emulator.getBackend().emu_stop();
    }

    private int munmap(Backend backend, Emulator<?> emulator) {
        long timeInMillis = System.currentTimeMillis();
        long start = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue() & 0xffffffffL;
        int length = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int ret = emulator.getMemory().munmap(start, length);
        if (log.isDebugEnabled()) {
            log.debug("munmap start=0x" + Long.toHexString(start) + ", length=" + length + ", ret=" + ret + ", offset=" + (System.currentTimeMillis() - timeInMillis) + ", from=" + UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
        }
        return ret;
    }

    private static final int PR_GET_DUMPABLE = 3;
    private static final int PR_SET_DUMPABLE = 4;
    private static final int PR_SET_NAME = 15;
    private static final int PR_GET_NAME = 16;
    private static final int BIONIC_PR_SET_VMA =              0x53564d41;
    private static final int PR_SET_PTRACER = 0x59616d61;

    private int prctl(Backend backend, Emulator<?> emulator) {
        int option = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        long arg2 = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("prctl option=0x" + Integer.toHexString(option) + ", arg2=0x" + Long.toHexString(arg2));
        }
        switch (option) {
            case PR_GET_DUMPABLE:
            case PR_SET_DUMPABLE:
                return 0;
            case PR_SET_NAME: {
                Pointer threadName = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                String name = threadName.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("prctl set thread name: " + name);
                }
                return 0;
            }
            case PR_GET_NAME: {
                String name = Thread.currentThread().getName();
                if (name.length() > 15) {
                    name = name.substring(0, 15);
                }
                if (log.isDebugEnabled()) {
                    log.debug("prctl get thread name: " + name);
                }
                Pointer buffer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                buffer.setString(0, name);
                return 0;
            }
            case BIONIC_PR_SET_VMA:
                Pointer addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int len = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
                Pointer pointer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
                if (log.isDebugEnabled()) {
                    log.debug("prctl set vma addr=" + addr + ", len=" + len + ", pointer=" + pointer + ", name=" + pointer.getString(0));
                }
                return 0;
            case PR_SET_PTRACER:
                int pid = (int) arg2;
                if (log.isDebugEnabled()) {
                    log.debug("prctl set ptracer: " + pid);
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

    private final long nanoTime = System.nanoTime();

    protected int clock_gettime(Backend backend, Emulator<?> emulator) {
        int clk_id = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer tp = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
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
                tp.setInt(0, (int) tv_sec);
                tp.setInt(4, (int) tv_nsec);
                return 0;
        }
        throw new UnsupportedOperationException("clk_id=" + clk_id);
    }

    private int fcntl(Backend backend, Emulator<?> emulator) {
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int cmd = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int arg = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        return fcntl(emulator, fd, cmd, arg);
    }

    private int writev(Backend backend, Emulator<?> emulator) {
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer iov = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int iovcnt = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        if (log.isDebugEnabled()) {
            for (int i = 0; i < iovcnt; i++) {
                Pointer iov_base = iov.getPointer(i * 8L);
                int iov_len = iov.getInt(i * 8L + 4);
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
            Pointer iov_base = iov.getPointer(i * 8L);
            int iov_len = iov.getInt(i * 8L + 4);
            byte[] data = iov_base.getByteArray(0, iov_len);
            count += file.write(data);
        }
        return count;
    }

    private static final int FUTEX_WAIT = 0;
    private static final int FUTEX_WAKE = 1;

    private int futex(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer uaddr = context.getPointerArg(0);
        int futex_op = context.getIntArg(1);
        int val = context.getIntArg(2);
        int old = uaddr.getInt(0);
        if (log.isDebugEnabled()) {
            log.debug("futex uaddr=" + uaddr + ", _futexop=" + futex_op + ", op=" + (futex_op & 0x7f) + ", val=" + val + ", old=" + old);
        }

        switch (futex_op & 0x7f) {
            case FUTEX_WAIT:
                if (old != val) {
                    throw new IllegalStateException("old=" + old + ", val=" + val);
                }
                Thread.yield();
                Pointer timeout = context.getPointerArg(3);
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

    private int brk(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        long address = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("brk address=0x" + Long.toHexString(address));
        }
        return emulator.getMemory().brk(address);
    }

    private int mprotect(Backend backend, Emulator<?> emulator) {
        long address = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue() & 0xffffffffL;
        int length = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int prot = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        long alignedAddress = address / ARMEmulator.PAGE_ALIGN * ARMEmulator.PAGE_ALIGN; // >> 12 << 12;
        long offset = address - alignedAddress;

        long alignedLength = ARM.alignSize(length + offset, emulator.getPageAlign());
        if (log.isDebugEnabled()) {
            log.debug("mprotect address=0x" + Long.toHexString(address) + ", alignedAddress=0x" + Long.toHexString(alignedAddress) + ", offset=" + offset + ", length=" + length + ", alignedLength=" + alignedLength + ", prot=0x" + Integer.toHexString(prot));
        }
        return emulator.getMemory().mprotect(alignedAddress, (int) alignedLength, prot);
    }

    private static final int MMAP2_SHIFT = 12;

    private int mmap2(Backend backend, Emulator<?> emulator) {
        long start = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue() & 0xffffffffL;
        int length = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int prot = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
        int offset = backend.reg_read(ArmConst.UC_ARM_REG_R5).intValue() << MMAP2_SHIFT;

        boolean warning = length >= 0x10000000;
        if (log.isDebugEnabled() || warning) {
            String msg = "mmap2 start=0x" + Long.toHexString(start) + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset + ", from=" + UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
            if (warning) {
                log.warn(msg);
            } else {
                log.debug(msg);
            }
        }
        return (int) emulator.getMemory().mmap2(start, length, prot, flags, fd, offset);
    }

    private int gettimeofday(Emulator<?> emulator) {
        Pointer tv = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer tz = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        return gettimeofday(emulator, tv, tz);
    }

    private int faccessat(Backend backend, Emulator<AndroidFileIO> emulator) {
        int dirfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer pathname_p = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int oflags = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int mode = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        String pathname = pathname_p.getString(0);
        String msg = "faccessat dirfd=" + dirfd + ", pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode);
        if (log.isDebugEnabled()) {
            log.debug(msg);
        }
        int ret = faccessat(emulator, pathname);
        if (ret == -1) {
            log.info(msg);
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

    private int fstatat64(Backend backend, Emulator<AndroidFileIO> emulator) {
        int dirfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer pathname = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer statbuf = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        String path = FilenameUtils.normalize(pathname.getString(0), true);
        if (log.isDebugEnabled()) {
            log.debug("fstatat64 dirfd=" + dirfd + ", pathname=" + path + ", statbuf=" + statbuf + ", flags=" + flags);
        }
        if (dirfd != IO.AT_FDCWD && !path.startsWith("/")) {
            throw new BackendException();
        }
        return stat64(emulator, path, statbuf);
    }

    private int mkdirat(Backend backend, Emulator<?> emulator) {
        int dirfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer pathname_p = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int mode = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        String pathname = pathname_p.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("mkdirat dirfd=" + dirfd + ", pathname=" + pathname + ", mode=" + Integer.toHexString(mode));
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int openat(Backend backend, Emulator<AndroidFileIO> emulator) {
        int dirfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer pathname_p = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int oflags = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int mode = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        String pathname = pathname_p.getString(0);
        String msg = "openat dirfd=" + dirfd + ", pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode);
        if (log.isDebugEnabled()) {
            log.debug(msg);
        }
        pathname = FilenameUtils.normalize(pathname, true);
        if ("/data/misc/zoneinfo/current/tzdata".equals(pathname) || "/dev/pmsg0".equals(pathname)) {
            emulator.getMemory().setErrno(UnixEmulator.ENOENT);
            return -1;
        }
        if (pathname.startsWith("/")) {
            int fd = open(emulator, pathname, oflags);
            if (fd == -1) {
                emulator.getMemory().setErrno(UnixEmulator.ENOENT);
                log.info(msg);
            }
            return fd;
        } else {
            if (dirfd != IO.AT_FDCWD) {
                throw new BackendException();
            }

            log.warn(msg);
            emulator.getMemory().setErrno(UnixEmulator.ENOENT);
            return -1;
        }
    }

    private int open(Emulator<AndroidFileIO> emulator) {
        Backend backend = emulator.getBackend();
        Pointer pathname_p = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int oflags = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int mode = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        String pathname = pathname_p.getString(0);
        String msg = "open pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode) + ", from=" + UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
        if (log.isDebugEnabled()) {
            log.debug(msg);
        }
        int fd = open(emulator, pathname, oflags);
        if (fd == -1) {
            log.info(msg);
        }
        return fd;
    }

    private int ftruncate(Backend backend) {
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int length = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
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
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int offset = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int whence = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int pos = file.lseek(offset, whence);
        if (log.isDebugEnabled()) {
            log.debug("lseek fd=" + fd + ", offset=" + offset + ", whence=" + whence + ", pos=" + pos + ", from=" + UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
        }
        return pos;
    }

    private int close(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        if (log.isDebugEnabled()) {
            log.debug("close fd=" + fd);
        }

        return close(emulator, fd);
    }

    private int getdents64(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        UnidbgPointer dirp = context.getPointerArg(1);
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

    private int fstat(Backend backend, Emulator<?> emulator) {
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer stat = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
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
        return file.fstat(emulator, new Stat32(stat));
    }

    private int ioctl(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        long request = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue() & 0xffffffffL;
        long argp = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue() & 0xffffffffL;
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
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer buffer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        return write(emulator, fd, buffer, count);
    }

    private int read(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer buffer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        return read(emulator, fd, buffer, count);
    }

    private int dup2(Backend backend, Emulator<?> emulator) {
        int oldfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int newfd = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        if (log.isDebugEnabled()) {
            log.debug("dup2 oldfd=" + oldfd + ", newfd=" + newfd);
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
