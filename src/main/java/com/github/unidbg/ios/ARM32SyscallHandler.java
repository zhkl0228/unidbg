package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.StopEmulatorException;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.file.ios.IOConstants;
import com.github.unidbg.ios.file.ByteArrayFileIO;
import com.github.unidbg.ios.file.LocalDarwinUdpSocket;
import com.github.unidbg.ios.struct.kernel.*;
import com.github.unidbg.ios.struct.sysctl.KInfoProc32;
import com.github.unidbg.ios.struct.sysctl.TaskDyldInfo;
import com.github.unidbg.linux.file.DriverFileIO;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.pointer.UnicornStructure;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.unix.file.SocketIO;
import com.github.unidbg.unix.file.TcpSocket;
import com.github.unidbg.unix.file.UdpSocket;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornConst;
import unicorn.UnicornException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * http://androidxref.com/4.4.4_r1/xref/external/kernel-headers/original/asm-arm/unistd.h
 */
public class ARM32SyscallHandler extends UnixSyscallHandler<DarwinFileIO> implements SyscallHandler<DarwinFileIO>, DarwinSyscall {

    private static final Log log = LogFactory.getLog(ARM32SyscallHandler.class);

    private final SvcMemory svcMemory;

    ARM32SyscallHandler(SvcMemory svcMemory) {
        super();

        this.svcMemory = svcMemory;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void hook(Unicorn u, int intno, Object user) {
        Emulator<DarwinFileIO> emulator = (Emulator<DarwinFileIO>) user;
        UnicornPointer pc = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
        final boolean isThumb = ARM.isThumb(u);
        final int bkpt;
        if (ARM.isThumb(u)) {
            bkpt = pc.getShort(0) & 0xff;
        } else {
            int instruction = pc.getInt(0);
            bkpt = (instruction & 0xf) | ((instruction >> 8) & 0xfff) << 4;
        }

        if (intno == ARMEmulator.EXCP_BKPT) { // bkpt
            emulator.attach().brk(pc, bkpt);
            return;
        }

        if (intno != ARMEmulator.EXCP_SWI) {
            throw new UnicornException("intno=" + intno);
        }

        final int svcNumber;
        if (isThumb) {
            svcNumber = pc.getShort(-2) & 0xff;
        } else {
            svcNumber = pc.getInt(-4) & 0xffffff;
        }

        int NR = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R12)).intValue();
        String syscall = null;
        Throwable exception = null;
        try {
            if (svcNumber == 0 && (((Number) u.reg_read(ArmConst.UC_ARM_REG_R5)).intValue()) == Svc.CALLBACK_SYSCALL_NUMBER && (((Number) u.reg_read(ArmConst.UC_ARM_REG_R7)).intValue()) == 0) { // callback
                int number = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handleCallback(emulator);
                    return;
                }
                u.emu_stop();
                throw new IllegalStateException("svc number: " + svcNumber);
            }
            if (svcNumber != DARWIN_SWI_SYSCALL) {
                Svc svc = svcMemory.getSvc(svcNumber);
                if (svc != null) {
                    u.reg_write(ArmConst.UC_ARM_REG_R0, (int) svc.handle(emulator));
                    return;
                }
                u.emu_stop();
                throw new IllegalStateException("svc number: " + svcNumber + ", NR=" + NR);
            }

            if (log.isDebugEnabled()) {
                ARM.showThumbRegs(emulator);
            }

            Cpsr.getArm(u).setCarry(false);
            if (handleSyscall(emulator, NR)) {
                return;
            }

            switch (NR) {
                case -3:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, mach_absolute_time(emulator));
                    return;
                case -10:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_vm_allocate_trap(emulator));
                    return;
                case -12:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_vm_deallocate_trap(emulator));
                    return;
                case -15:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_vm_map_trap(emulator));
                    return;
                case -16:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_allocate_trap(emulator));
                    return;
                case -18:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_deallocate_trap(emulator));
                    return;
                case -19:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_mod_refs_trap(emulator));
                    return;
                case -21:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_insert_right_trap(emulator));
                    return;
                case -24:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_construct_trap(emulator));
                    return;
                case -26: // mach_port_t mach_reply_port(...)
                    u.reg_write(ArmConst.UC_ARM_REG_R0, mach_reply_port());
                    return;
                case -27:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, thread_self_trap());
                    return;
                case -28: // mach_port_name_t task_self_trap(void)
                    u.reg_write(ArmConst.UC_ARM_REG_R0, task_self_trap());
                    return;
                case -29:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, host_self_trap());
                    return;
                case -31:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, mach_msg_trap(emulator));
                    return;
                case -36: // _semaphore_wait_trap
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _semaphore_wait_trap(emulator));
                    return;
                case -41: // _xpc_mach_port_guard
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_guard_trap(emulator));
                    return;
                case -61:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, thread_switch(emulator));
                    return;
                case -89:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _mach_timebase_info(emulator));
                    return;
                case 4:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, write(u, emulator));
                    return;
                case 6:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, close(u, emulator));
                    return;
                case 10:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, unlink(emulator));
                    return;
                case 20:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, getpid(emulator));
                    return;
                case 24: // getuid
                case 25: // geteuid
                case 43: // getegid
                case 47: // getgid
                    if (log.isDebugEnabled()) {
                        log.debug("NR=" + NR);
                    }
                    u.reg_write(ArmConst.UC_ARM_REG_R0, 0);
                    return;
                case 33:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, access(u, emulator));
                    return;
                case 58:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, readlink(u, emulator));
                    return;
                case 46:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, sigaction(u, emulator));
                    return;
                case 48:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, sigprocmask(u, emulator));
                    return;
                case 73:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, munmap(u, emulator));
                    return;
                case 74:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, mprotect(u, emulator));
                    return;
                case 75:
                    syscall = "posix_madvise";
                    u.reg_write(ArmConst.UC_ARM_REG_R0, 0);
                    return;
                case 92:
                case 406: // fcntl_NOCANCEL
                    u.reg_write(ArmConst.UC_ARM_REG_R0, fcntl(u, emulator));
                    return;
                case 97:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, socket(u, emulator));
                    return;
                case 98:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, connect(u, emulator));
                    return;
                case 116:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, gettimeofday(emulator));
                    return;
                case 133:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, sendto(u, emulator));
                    return;
                case 194:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, getrlimit(u, emulator));
                    return;
                case 197:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, mmap(u, emulator));
                    return;
                case 199:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, lseek(u, emulator));
                    return;
                case 202:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, sysctl(emulator));
                    return;
                case 286:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, pthread_getugid_np(emulator));
                    return;
                case 301:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, psynch_mutexwait(emulator));
                    return;
                case 302:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, psynch_mutexdrop(emulator));
                    return;
                case 305:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, psynch_cvwait());
                    return;
                case 327:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, issetugid());
                    return;
                case 329:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, pthread_sigmask(emulator));
                    return;
                case 336:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, proc_info(emulator));
                    return;
                case 338:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, stat64(emulator));
                    return;
                case 339:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, fstat(u, emulator));
                    return;
                case 340:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, lstat(emulator));
                    return;
                case 344:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, getdirentries64(u, emulator));
                    return;
                case 346:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, fstatfs64(u, emulator));
                    return;
                case 357:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, getaudit_addr(u, emulator));
                    return;
                case 360:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, bsdthread_create(emulator));
                    return;
                case 366:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, bsdthread_register(emulator));
                    return;
                case 367:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _workq_open());
                    return;
                case 368:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, _workq_kernreturn());
                    return;
                case 369:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, kevent64(emulator));
                    return;
                case 372:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, thread_selfid());
                    return;
                case 381:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, sandbox_ms(emulator));
                    return;
                case 396:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, read_NOCANCEL(emulator));
                    return;
                case 397:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, write_NOCANCEL(emulator));
                    return;
                case 5: // unix open
                case 398:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, open_NOCANCEL(emulator));
                    return;
                case 266:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, shm_open(emulator));
                    return;
                case 399:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, close_NOCANCEL(emulator));
                    return;
                case 423:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, semwait_signal_nocancel());
                    return;
                case 428:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, audit_session_self());
                    return;
                case 443:
                    u.reg_write(ArmConst.UC_ARM_REG_R0, guarded_kqueue_np(emulator));
                    return;
                case 0x80000000:
                    NR = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                    if(handleMachineDependentSyscall(emulator, u, NR)) {
                        return;
                    }
                default:
                    break;
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

        log.warn("handleInterrupt intno=" + intno + ", NR=" + NR + ", svcNumber=0x" + Integer.toHexString(svcNumber) + ", PC=" + pc + ", syscall=" + syscall, exception);

        if (exception instanceof UnicornException) {
            throw (UnicornException) exception;
        }
    }

    private boolean handleMachineDependentSyscall(Emulator<?> emulator, Unicorn u, int NR) {
        switch (NR) {
            case 0:
                u.reg_write(ArmConst.UC_ARM_REG_R0, sys_icache_invalidate(emulator));
                return true;
            case 1:
                u.reg_write(ArmConst.UC_ARM_REG_R0, sys_dcache_flush(emulator));
                return true;
            case 2:
                u.reg_write(ArmConst.UC_ARM_REG_R0, pthread_set_self(emulator));
                return true;
        }
        return false;
    }

    private int pthread_set_self(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer self = context.getPointerArg(0);
        Pthread pthread = new Pthread32(self.getPointer(0));
        pthread.unpack();
        UnicornPointer tsd = pthread.getTSD();
        emulator.getUnicorn().reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tsd.peer);
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setErrnoPointer(pthread.getErrno());

        if (log.isDebugEnabled()) {
            String threadName = pthread.getName();
            log.debug("pthread_set_self=" + self + ", pthread=" + pthread + ", threadName=" + threadName + ", LR=" + emulator.getContext().getLRPointer());
        }
        return 0;
    }

    private int sys_dcache_flush(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer address = context.getPointerArg(0);
        long size = context.getLongArg(1);
        if (log.isDebugEnabled()) {
            log.debug("sys_dcache_flush address=" + address + ", size=" + size);
        }
        return 0;
    }

    private int sys_icache_invalidate(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer address = context.getPointerArg(0);
        long size = context.getLongArg(1);
        if (log.isDebugEnabled()) {
            log.debug("sys_icache_invalidate address=" + address + ", size=" + size);
        }
        return 0;
    }

    private int pthread_getugid_np(Emulator<?> emulator) {
        Pointer uid = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer gid = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        if (log.isDebugEnabled()) {
            log.debug("pthread_getugid_np uid=" + uid + ", gid=" + gid);
        }
        uid.setInt(0, 0);
        gid.setInt(0, 0);
        return 0;
    }

    private int _mach_timebase_info(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pointer = context.getPointerArg(0);
        MachTimebaseInfo info = new MachTimebaseInfo(pointer);
        info.denom = 1;
        info.numer = 1;
        info.pack();
        if (log.isDebugEnabled()) {
            log.debug("_mach_timebase_info info=" + info + ", LR=" + context.getLRPointer());
        }
        return 0;
    }

    private int readlink(Unicorn u, Emulator<?> emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int bufSize = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        String path = pathname.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("readlink path=" + path + ", buf=" + buf + ", bufSize=" + bufSize);
        }
        if ("/var/db/timezone/localtime".equals(path)) { // 设置时区
            path = "/var/db/timezone/zoneinfo/Asia/Shanghai";
        }
        buf.setString(0, path);
        return path.length() + 1;
    }

    private int psynch_mutexdrop(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer mutex = context.getPointerArg(0);
        int mgen = context.getIntArg(1);
        int ugen = context.getIntArg(2);
        long tid = context.getR3Int();
        int flags = context.getR5Int();
        if (log.isDebugEnabled()) {
            log.debug("psynch_mutexdrop mutex=" + mutex + ", mgen=" + mgen + ", ugen=" + ugen + ", tid=" + tid + ", flags=0x" + Integer.toHexString(flags) + ", LR=" + context.getLRPointer());
        }
        return 0;
    }

    private int psynch_mutexwait(Emulator<?> emulator) {
        // TODO: implement
        Arm32RegisterContext context = emulator.getContext();
        Pointer mutex = context.getPointerArg(0);
        int mgen = context.getIntArg(1);
        int ugen = context.getIntArg(2);
        long tid = context.getR3Int();
        int flags = context.getR5Int();
        if (log.isDebugEnabled()) {
            log.debug("psynch_mutexwait mutex=" + mutex + ", mgen=" + mgen + ", ugen=" + ugen + ", tid=" + tid + ", flags=0x" + Integer.toHexString(flags) + ", LR=" + context.getLRPointer());
        }
        return 0;
    }

    private int bsdthread_create(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        Pointer start_routine = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer arg = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer stack = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        UnicornPointer thread = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        int flags = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        if (thread == null) {
            MemoryBlock memoryBlock = emulator.getMemory().malloc(0x100, true);
            thread = memoryBlock.getPointer();
        }
        log.info("bsdthread_create start_routine=" + start_routine + ", arg=" + arg + ", stack=" + stack + ", thread=" + thread + ", flags=0x" + Integer.toHexString(flags));
        return (int) thread.peer;
    }

    private int _workq_open() {
        // TODO: implement
        log.info("_workq_open");
        return 0;
    }

    private int _workq_kernreturn() {
        // TODO: implement
        log.info("_workq_kernreturn");
        return 0;
    }

    private int guarded_kqueue_np(Emulator<?> emulator) {
        // TODO: implement
        Unicorn unicorn = emulator.getUnicorn();
        Pointer guard = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int guardFlags = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        log.info("guarded_kqueue_np guard=" + guard + ", guardFlags=0x" + Integer.toHexString(guardFlags));
        return 0;
    }

    private int kevent64(Emulator<?> emulator) {
        // TODO: implement
        Arm32RegisterContext context = emulator.getContext();
        int kq = context.getIntArg(0);
        Pointer changelist = context.getPointerArg(1);
        int nchanges = context.getIntArg(2);
        Pointer eventlist = context.getPointerArg(3);
        int nevents = context.getR4Int();
        int flags = context.getR5Int();
        Pointer timeout = context.getR6Pointer();
        log.info("kevent64 kq=" + kq + ", changelist=" + changelist + ", nchanges=" + nchanges + ", eventlist=" + eventlist + ", nevents=" + nevents + ", flags=0x" + Integer.toHexString(flags) + ", timeout=" + timeout + ", LR=" + context.getLRPointer());
        return 0;
    }

    private int _kernelrpc_mach_port_allocate_trap(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int task = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int right = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        Pointer name = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_allocate_trap task=" + task + ", right=" + right + ", name=" + name);
        }
        name.setInt(0, STATIC_PORT);
        return 0;
    }

    private int _kernelrpc_mach_port_insert_right_trap(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int task = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int name = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int poly = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int polyPoly = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_insert_right_trap task=" + task + ", name=" + name + ", poly=" + poly + ", polyPoly=" + polyPoly);
        }
        return 0;
    }

    private long _semaphore_wait_trap(Emulator<?> emulator) {
        int port = emulator.getContext().getIntArg(0);
        log.info("_semaphore_wait_trap port=" + port);
        Log log = ARM32SyscallHandler.log;
        if (!log.isDebugEnabled()) {
            log = LogFactory.getLog(AbstractEmulator.class);
        }
        if (log.isDebugEnabled()) {
            emulator.attach().debug();
        }
        return 0;
    }

    private long _kernelrpc_mach_port_guard_trap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int task = context.getIntArg(0);
        int name = context.getIntArg(1);
        Pointer guard = context.getPointerArg(2);
        int strict = context.getIntArg(3);
        log.info("_kernelrpc_mach_port_guard_trap task=" + task + ", name=" + name + ", guard=" + guard + ", strict=" + strict);
        return 0;
    }

    private int thread_switch(Emulator<?> emulator) {
        // TODO: implement
        Unicorn unicorn = emulator.getUnicorn();
        int thread_name = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int option = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int option_time = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        log.info("thread_switch thread_name=" + thread_name + ", option=" + option + ", option_time=" + option_time);
        return 0;
    }

    private int psynch_cvwait() {
        // TODO: implement
        log.info("psynch_cvwait");
        return 0;
    }

    private int close(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
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

    private int lseek(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int r1 = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        long r2 = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        long offset = r1 | (r2 << 32);
        int whence = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        FileIO file = fdMap.get(fd);
        if (file == null) {
            if (log.isDebugEnabled()) {
                log.debug("lseek fd=" + fd + ", offset=" + offset + ", whence=" + whence);
            }
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int pos = file.lseek((int) offset, whence);
        if (log.isDebugEnabled()) {
            log.debug("lseek fd=" + fd + ", offset=" + offset + ", whence=" + whence + ", pos=" + pos);
        }
        return pos;
    }

    private int unlink(Emulator<?> emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        String path = FilenameUtils.normalize(pathname.getString(0));
        emulator.getFileSystem().unlink(path);
        return 0;
    }

    private int getdirentries64(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int bufSize = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        Pointer basep = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        if (log.isDebugEnabled()) {
            log.debug("getdirentries64 fd=" + fd + ", buf=" + buf + ", bufSize=" + bufSize + ", basep=" + basep);
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int fstatfs64(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        if (log.isDebugEnabled()) {
            log.debug("fstatfs64 fd=" + fd + ", buf=" + buf);
        }
        DarwinFileIO io = fdMap.get(fd);
        if (io != null) {
            return io.fstatfs(new StatFS(buf));
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int access(Unicorn u, Emulator<DarwinFileIO> emulator) {
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

    private int faccessat(Emulator<DarwinFileIO> emulator, String pathname) {
        FileResult<?> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            return 0;
        }

        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.EACCES);
        return -1;
    }

    private int stat64(Emulator<DarwinFileIO> emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer statbuf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        String path = pathname.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("stat64 pathname=" + path + ", statbuf=" + statbuf);
        }
        return stat64(emulator, FilenameUtils.normalize(path), statbuf);
    }

    protected int fstat(Emulator<DarwinFileIO> emulator, int fd, Pointer stat) {
        if (log.isDebugEnabled()) {
            log.debug("fstat fd=" + fd + ", stat=" + stat);
        }

        DarwinFileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        if (log.isDebugEnabled()) {
            log.debug("fstat file=" + file + ", stat=" + stat);
        }
        return file.fstat(emulator, new Stat(stat));
    }

    protected int stat64(Emulator<DarwinFileIO> emulator, String pathname, Pointer statbuf) {
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            return result.io.fstat(emulator, new Stat(statbuf));
        }

        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.EACCES);
        return -1;
    }

    private int write_NOCANCEL(Emulator<?> emulator) {
        Unicorn u = emulator.getUnicorn();
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        return write(emulator, fd, buffer, count);
    }

    private int fstat(Unicorn u, Emulator<DarwinFileIO> emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer stat = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        return fstat(emulator, fd, stat);
    }

    /**
     * lstat() is identical to stat(), except that if pathname is a symbolic link, then it returns information about the link itself, not the file that it refers to.
     */
    private int lstat(Emulator<DarwinFileIO> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer pathname = context.getR0Pointer();
        Pointer stat = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        String path = FilenameUtils.normalize(pathname.getString(0));
        if (log.isDebugEnabled()) {
            log.debug("lstat path=" + path + ", stat=" + stat);
        }
        return stat64(emulator, path, stat);
    }

    private static final int RLIMIT_NOFILE = 8;		/* number of open files */
    private static final int RLIMIT_POSIX_FLAG = 0x1000;	/* Set bit for strict POSIX */

    private int getrlimit(Unicorn u, Emulator<?> emulator) {
        int resource = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer rlp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        boolean posix = (resource & RLIMIT_POSIX_FLAG) != 0;
        int type = resource & (RLIMIT_POSIX_FLAG - 1);
        String msg = "getrlimit resource=0x" + Integer.toHexString(resource) + ", rlp=" + rlp + ", posix=" + posix + ", type=" + type;
        if (type == RLIMIT_NOFILE) {
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            RLimit rLimit = new RLimit(rlp);
            rLimit.rlim_cur = 128;
            rLimit.rlim_max = 256;
            rLimit.pack();
            return 0;
        } else {
            log.info(msg);
        }
        return 1;
    }

    private int _kernelrpc_mach_port_mod_refs_trap(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int task = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int name = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int right = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int delta = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_mod_refs_trap task=" + task + ", name=" + name + ", right=" + right + ", delta=" + delta);
        }
        return 0;
    }

    private int _kernelrpc_mach_port_construct_trap(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int task = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer options = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int r2 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        long r3 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        long context = r2 | (r3 << 32);
        Pointer name = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        if (log.isDebugEnabled()) {
            MachPortOptions portOptions = new MachPortOptions(options);
            portOptions.unpack();
            log.debug("_kernelrpc_mach_port_construct_trap task=" + task + ", options=" + options + ", context=0x" + Long.toHexString(context) + ", name=" + name + ", portOptions=" + portOptions);
        }
        name.setInt(0, 0x88);
        return 0;
    }

    private int getaudit_addr(Unicorn u, Emulator<?> emulator) {
        Pointer addr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("getaudit_addr=" + addr + ", size=" + size);
        }
        return 0;
    }

    private static final int PROC_INFO_CALL_SETCONTROL = 0x5;
    private static final int PROC_SELFSET_THREADNAME = 2;

    private static final int PROC_INFO_CALL_PIDINFO = 0x2;
    private static final int PROC_PIDT_SHORTBSDINFO = 13;

    private int proc_info(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int callNum = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int pid = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int flavor = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int r3 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        long r4 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        long arg = r3 | (r4 << 32);
        Pointer buffer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R5);
        int bufferSize = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R6)).intValue();

        String msg = "proc_info callNum=" + callNum + ", pid=" + pid + ", flavor=" + flavor + ", arg=" + arg + ", buffer=" + buffer + ", bufferSize=" + bufferSize;
        if (PROC_INFO_CALL_SETCONTROL == callNum && PROC_SELFSET_THREADNAME == flavor) {
            String threadName = buffer.getString(0);
            if (log.isDebugEnabled()) {
                log.debug(msg + ", threadName=" + threadName);
            }
            return 0;
        } else if (PROC_INFO_CALL_PIDINFO == callNum && PROC_PIDT_SHORTBSDINFO == flavor) {
            ProcBsdShortInfo info = new ProcBsdShortInfo(buffer);
            info.unpack();

            String processName = emulator.getProcessName();
            if (processName == null) {
                processName = "unidbg";
            }
            info.pbsi_pid = pid;
            info.pbsi_status = ProcBsdShortInfo.SRUN;
            info.pbsi_comm = Arrays.copyOf(Arrays.copyOf(processName.getBytes(), DarwinSyscall.MAXCOMLEN-1), DarwinSyscall.MAXCOMLEN);
            info.pbsi_flags = 0x24090;
            info.pbsi_uid = 0;
            info.pbsi_ruid = 0;
            info.pbsi_svuid = 0;
            info.pbsi_gid = 0;
            info.pbsi_rgid = 0;
            info.pbsi_svgid = 0;
            info.pbsi_pgid = 0;
            info.pbsi_ppid = pid - 1;
            info.pack();
            if (log.isDebugEnabled()) {
                log.debug(msg + ", info=" + info);
            }
            return info.size();
        } else {
            log.info(msg);
            return 1;
        }
    }

    private int semwait_signal_nocancel() {
        // TODO: implement
        log.info("semwait_signal_nocancel");
        return 0;
    }

    private int pthread_sigmask(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int how = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer set = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oset = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        if (log.isDebugEnabled()) {
            log.debug("pthread_sigmask how=" + how + ", set=" + set + ", oset=" + oset);
        }
        return 0;
    }

    private int sandbox_ms(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        Pointer policyName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int call = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        Pointer args = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        if (log.isDebugEnabled()) {
            log.debug("sandbox_ms policyName=" + policyName.getString(0) + ", call=" + call + ", args=" + args);
        }
        return 0;
    }

    private int issetugid() {
        log.debug("issetugid");
        return 0;
    }

    private int bsdthread_register(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        UnicornPointer thread_start = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        UnicornPointer start_wqthread = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int PTHREAD_SIZE = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        UnicornPointer data = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        int dataSize = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        int r5 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R5)).intValue();
        long r6 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R6)).intValue();
        long offset = r5 | (r6 << 32);
        if (log.isDebugEnabled()) {
            log.debug("bsdthread_register thread_start=" + thread_start + ", start_wqthread=" + start_wqthread + ", PTHREAD_SIZE=" + PTHREAD_SIZE + ", data=" + data + ", dataSize=" + dataSize + ", offset=0x" + Long.toHexString(offset));
        }
        return 0;
    }

    private int munmap(Unicorn u, Emulator<?> emulator) {
        long timeInMillis = System.currentTimeMillis();
        long start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue() & 0xffffffffL;
        int length = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int ret = emulator.getMemory().munmap(start, length);
        if (log.isDebugEnabled()) {
            log.debug("munmap start=0x" + Long.toHexString(start) + ", length=" + length + ", ret=" + ret + ", offset=" + (System.currentTimeMillis() - timeInMillis));
        }
        return ret;
    }

    private static final int CTL_UNSPEC = 0; /* unused */
    private static final int CTL_KERN = 1; /* "high kernel": proc, limits */
    private static final int CTL_HW = 6; /* generic cpu/io */

    private static final int KERN_OSRELEASE = 2; /* string: system release */
    private static final int KERN_ARGMAX = 8; /* int: max arguments to exec */
    private static final int KERN_HOSTNAME = 10; /* string: hostname */
    private static final int KERN_PROC = 14; /* struct: process entries */
    private static final int KERN_USRSTACK32 = 35; /* int: address of USRSTACK */
    private static final int KERN_PROCARGS2 = 49;
    private static final int KERN_OSVERSION = 65; /* for build number i.e. 9A127 */

    private static final int HW_PAGESIZE = 7; /* int: software page size */

    private static final int KERN_PROC_PID = 1; /* by process id */

    private int sysctl(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        Pointer name = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int namelen = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        Pointer bufferSize = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        Pointer set0 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        int set1 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R5)).intValue();

        int top = name.getInt(0);
        switch (top) {
            case CTL_UNSPEC:
                int action = name.getInt(4);
                if (action == 3) {
                    String sub = set0.getString(0);
                    if (log.isDebugEnabled()) {
                        log.debug("sysctl CTL_UNSPEC action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", sub=" + sub);
                    }
                    if ("kern.osrelease".equals(sub)) {
                        buffer.setInt(0, CTL_KERN);
                        buffer.setInt(4, KERN_OSRELEASE);
                        bufferSize.setInt(0, 8);
                        return 0;
                    }
                    return 1;
                }
                log.info("sysctl CTL_UNSPEC action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1);
                break;
            case CTL_KERN:
                action = name.getInt(4);
                String msg = "sysctl CTL_KERN action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1;
                switch (action) {
                    case KERN_PROCARGS2:
                        log.info(msg);
                        return 1;
                    case KERN_OSRELEASE:
                        log.debug(msg);
                        String osRelease = "7.1.2";
                        if (bufferSize != null) {
                            bufferSize.setInt(0, osRelease.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, osRelease);
                        }
                        return 0;
                    case KERN_ARGMAX:
                        bufferSize.setInt(0, 4);
                        buffer.setInt(0, 128);
                        return 0;
                    case KERN_HOSTNAME:
                        log.debug(msg);
                        String host = "localhost";
                        if (bufferSize != null) {
                            bufferSize.setInt(0, host.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, host);
                        }
                        return 0;
                    case KERN_PROC:
                        int subType = name.getInt(8);
                        if (subType == KERN_PROC_PID) {
                            int pid = name.getInt(0xc);
                            KInfoProc32 kInfoProc = new KInfoProc32(buffer);
                            kInfoProc.unpack();

                            kInfoProc.kp_eproc.e_ucred.cr_uid = 0;
                            kInfoProc.pack();
                            if (log.isDebugEnabled()) {
                                log.debug(msg + ", subType=" + subType + ", pid=" + pid + ", kInfoProc=" + kInfoProc);
                            }
                            return 0;
                        }
                        log.info(msg + ", subType=" + subType);
                        break;
                    case KERN_OSVERSION:
                        log.debug(msg);
                        String osVersion = "9A127";
                        if (bufferSize != null) {
                            bufferSize.setInt(0, osVersion.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, osVersion);
                        }
                        return 0;
                    case KERN_USRSTACK32:
                        if (bufferSize != null) {
                            bufferSize.setInt(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, (int) emulator.getMemory().getStackBase());
                        }
                        return 0;
                    default:
                        log.info(msg);
                        break;
                }
                break;
            case CTL_HW:
                action = name.getInt(4);
                msg = "sysctl CTL_HW action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1;
                if (action == HW_PAGESIZE) {
                    log.debug(msg);
                    if (bufferSize != null) {
                        bufferSize.setInt(0, 4);
                    }
                    if (buffer != null) {
                        buffer.setInt(0, emulator.getPageAlign());
                    }
                    return 0;
                }
                log.info(msg);
                break;
            default:
                log.info("sysctl top=" + name.getInt(0) + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1);
                break;
        }
        return 1;
    }

    private int _kernelrpc_mach_vm_deallocate_trap(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int target = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        long r1 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        long r2 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        long address = r1 | (r2 << 32);
        long r3 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        long r4 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        long size = r3 | (r4 << 32);

        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_deallocate_trap target=" + target + ", address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size));
        } else {
            Log log = LogFactory.getLog("com.github.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug("_kernelrpc_mach_vm_deallocate_trap target=" + target + ", address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
            }
        }
        if (size > 0) {
            emulator.getMemory().munmap(address, (int) size);
        }
        return 0;
    }

    private int _kernelrpc_mach_vm_map_trap(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int target = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer address = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int r2 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        long r3 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        long size = (r3 << 32) | r2;
        int r4 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        long r5 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R5)).intValue();
        long mask = (r5 << 32) | r4;
        int flags = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R6)).intValue();
        int cur_protection = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R8)).intValue();
        int tag = flags >> 24;
        boolean anywhere = (flags & MachO.VM_FLAGS_ANYWHERE) != 0;
        if (!anywhere) {
            throw new UnicornException("_kernelrpc_mach_vm_map_trap fixed");
        }

        Pointer value = address.getPointer(0);
        UnicornPointer pointer;
        if (mask != 0) {
            MachOLoader loader = (MachOLoader) emulator.getMemory();
            pointer = UnicornPointer.pointer(emulator, loader.allocate(size, mask));
        } else {
            pointer = emulator.getMemory().mmap((int) size, cur_protection);
        }
        String msg = "_kernelrpc_mach_vm_map_trap target=" + target + ", address=" + address + ", value=" + value + ", size=0x" + Long.toHexString(size) + ", mask=0x" + Long.toHexString(mask) + ", flags=0x" + Long.toHexString(flags) + ", cur_protection=" + cur_protection + ", pointer=" + pointer + ", anywhere=true, tag=0x" + Integer.toHexString(tag);
        if (log.isDebugEnabled()) {
            log.debug(msg);
        } else {
            Log log = LogFactory.getLog("com.github.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
        }
        address.setPointer(0, pointer);
        return 0;
    }

    private int _kernelrpc_mach_vm_allocate_trap(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int target = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer address = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        long r2 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        long r3 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        long size = r2 | (r3 << 32);
        int flags = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        int tag = flags >> 24;
        boolean anywhere = (flags & MachO.VM_FLAGS_ANYWHERE) != 0;
        if (!anywhere) {
            throw new UnicornException("_kernelrpc_mach_vm_allocate_trap fixed");
        }

        Pointer value = address.getPointer(0);
        UnicornPointer pointer = emulator.getMemory().mmap((int) size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);
        pointer.write(0, new byte[(int) size], 0, (int) size);
        address.setPointer(0, pointer);
        String str = "_kernelrpc_mach_vm_allocate_trap target=" + target + ", address=" + address + ", value=" + value + ", size=0x" + Long.toHexString(size) + ", flags=0x" + Integer.toHexString(flags) + ", pointer=" + pointer + ", anywhere=true, tag=0x" + Integer.toHexString(tag);
        if (log.isDebugEnabled()) {
            log.debug(str);
        } else {
            Log log = LogFactory.getLog("com.github.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug(str);
            }
        }
        return 0;
    }

    private int _kernelrpc_mach_port_deallocate_trap(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int task = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int name = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_deallocate_trap task=" + task + ", name=" + name);
        }
        return 0;
    }

    // https://github.com/lunixbochs/usercorn/blob/master/go/kernel/mach/thread.go
    private int thread_selfid() {
        log.debug("thread_selfid");
        return 1;
    }

    // https://github.com/lunixbochs/usercorn/blob/master/go/kernel/mach/ports.go
    private int mach_msg_trap(Emulator<?> emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        UnicornPointer msg = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int option = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int send_size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int rcv_size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        int rcv_name = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        int timeout = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R5)).intValue();
        int notify = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R6)).intValue();

        msg.setSize(Math.max(send_size, rcv_size));

        final MachMsgHeader header = new MachMsgHeader(msg);
        header.unpack();
        if (log.isDebugEnabled()) {
            log.debug("mach_msg_trap msg=" + msg + ", option=0x" + Integer.toHexString(option) + ", send_size=" + send_size + ", rcv_size=" + rcv_size + ", rcv_name=" + rcv_name + ", timeout=" + timeout + ", notify=" + notify + ", header=" + header);
        }

        final Pointer request = msg.share(header.size());

        switch (header.msgh_id) {
            case 3409: // task_get_special_port
            {
                TaskGetSpecialPortRequest args = new TaskGetSpecialPortRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("task_get_special_port request=" + args);
                }

                if (args.which == TASK_BOOTSTRAP_PORT) {
                    TaskGetSpecialPortReply reply = new TaskGetSpecialPortReply(request);
                    reply.unpack();

                    header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                    header.msgh_size = header.size() + reply.size();
                    header.msgh_remote_port = header.msgh_local_port;
                    header.msgh_local_port = 0;
                    header.msgh_id += 100; // reply Id always equals reqId+100
                    header.pack();

                    reply.body.msgh_descriptor_count = 1;
                    reply.port.name = BOOTSTRAP_PORT; // I just chose 11 randomly here
                    reply.port.pad1 = 0;
                    reply.port.pad2 = 0;
                    reply.port.disposition = 17; // meaning?
                    reply.port.type = MACH_MSG_PORT_DESCRIPTOR;
                    reply.pack();
                    if (log.isDebugEnabled()) {
                        log.debug("task_get_special_port reply=" + reply);
                    }

                    return MACH_MSG_SUCCESS;
                }
            }
            case 200: // host_info
            {
                HostInfoRequest args = new HostInfoRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("host_info args=" + args);
                }

                if (args.flavor == HOST_PRIORITY_INFO) {
                    HostInfoReply reply = new HostInfoReply(request);
                    reply.unpack();

                    header.msgh_bits &= 0xff;
                    header.msgh_size = header.size() + reply.size();
                    header.msgh_remote_port = header.msgh_local_port;
                    header.msgh_local_port = 0;
                    header.msgh_id += 100; // reply Id always equals reqId+100
                    header.pack();

                    reply.NDR = args.NDR;
                    reply.retCode = 0; // success
                    reply.host_info_outCnt = 8;
                    reply.host_info_out.kernel_priority = 0;
                    reply.host_info_out.system_priority = 0;
                    reply.host_info_out.server_priority = 0;
                    reply.host_info_out.user_priority = 0;
                    reply.host_info_out.depress_priority = 0;
                    reply.host_info_out.idle_priority = 0;
                    reply.host_info_out.minimum_priority = 10;
                    reply.host_info_out.maximum_priority = -10;
                    reply.pack();

                    if (log.isDebugEnabled()) {
                        log.debug("host_info reply=" + reply);
                    }
                    return MACH_MSG_SUCCESS;
                }
            }
            case 206: // host_get_clock_service
            {
                HostGetClockServiceRequest args = new HostGetClockServiceRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("host_get_clock_service args=" + args);
                }

                HostGetClockServiceReply reply = new HostGetClockServiceReply(request);
                reply.unpack();

                header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.clock_server.name = CLOCK_SERVER_PORT; // I just chose 13 randomly here
                reply.clock_server.pad1 = 0;
                reply.clock_server.pad2 = 0;
                reply.clock_server.disposition = 17; // meaning?
                reply.clock_server.type = MACH_MSG_PORT_DESCRIPTOR;
                reply.pack();
                if (log.isDebugEnabled()) {
                    log.debug("host_get_clock_service reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3418: // semaphore_create
            {
                SemaphoreCreateRequest args = new SemaphoreCreateRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("semaphore_create args=" + args);
                }

                SemaphoreCreateReply reply = new SemaphoreCreateReply(request);
                reply.unpack();

                header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.semaphore.name = SEMAPHORE_PORT; // I just chose 14 randomly here
                reply.semaphore.pad1 = 0;
                reply.semaphore.pad2 = 0;
                reply.semaphore.disposition = 17; // meaning?
                reply.semaphore.type = MACH_MSG_PORT_DESCRIPTOR;
                reply.pack();
                if (log.isDebugEnabled()) {
                    log.debug("semaphore_create reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3822: // vm_region_recurse_64
            {
                VmRegionRecurse32Request args = new VmRegionRecurse32Request(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_region_recurse_64 args=" + args);
                }

                VmRegionRecurse32Reply reply = new VmRegionRecurse32Reply(request);
                reply.unpack();

                header.msgh_bits &= 0xff;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                MemoryMap memoryMap = null;
                for (MemoryMap mm : emulator.getMemory().getMemoryMap()) {
                    if (args.getAddress() >= mm.base && args.getAddress() < mm.base + mm.size) {
                        memoryMap = mm;
                        break;
                    }
                }

                if (log.isDebugEnabled()) {
                    log.debug("vm_region_recurse_64 header=" + header + ", memoryMap=" + memoryMap);
                }

                if (memoryMap == null) {
                    log.warn("vm_region_recurse_64 failed address=0x" + args.address + ", size=0x" + Integer.toHexString(args.size()));
                    return -1;
                }

                reply.NDR = args.NDR;
                reply.retCode = 0; // success
                reply.address = (int) memoryMap.base;
                reply.size = (int) memoryMap.size;
                reply.infoCnt = 7;
                reply.nestingDepth = 0;
                reply.info.protection = memoryMap.prot;
                reply.info.max_protection = memoryMap.prot;
                reply.info.inheritance = memoryMap.prot;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("vm_region_recurse_64 reply=" + reply + ", memoryMap=" + memoryMap);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3414: // task_get_exception_ports
            {
                TaskGetExceptionPortsRequest args = new TaskGetExceptionPortsRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("task_get_exception_ports args=" + args + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }

                TaskGetExceptionPortsReply reply = new TaskGetExceptionPortsReply(request);
                reply.unpack();

                header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                args.NDR.mig_vers = 0x20;
                reply.NDR = args.NDR;
                reply.retCode = 0;
                reply.header = new int[32];
                reply.reserved = new byte[0x100];
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("task_get_exception_ports reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3404: // mach_ports_lookup
            {
                MachPortsLookupReply reply = new MachPortsLookupReply(request);
                reply.unpack();

                header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                header.msgh_size = 52;
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.retCode = 1;
                reply.outPort = request;
                reply.ret = 0;
                reply.mask = 0x2110000;
                reply.cnt = 0;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("mach_ports_lookup reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3808: // vm_copy
            {
                VmCopyRequest args = new VmCopyRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_copy args=" + args + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }

                byte[] data = unicorn.mem_read(args.source_address, args.size);
                unicorn.mem_write(args.dest_address, data);

                VmCopyReply reply = new VmCopyReply(request);
                reply.unpack();

                header.msgh_bits &= 0xff;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.retCode = 0;
                reply.NDR = args.NDR;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("vm_copy reply=" + reply + ", header=" + header);
                }
                return MACH_MSG_SUCCESS;
            }
            case 4813: // _kernelrpc_mach_vm_remap
            {
                VmRemapRequest args = new VmRemapRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("_kernelrpc_mach_vm_remap args=" + args + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }

                if (args.anywhere != MachO.VM_FLAGS_OVERWRITE || args.mask != 0) {
                    throw new UnsupportedOperationException();
                }

                unicorn.mem_unmap(args.target_address, args.size);
                unicorn.mem_map(args.target_address, args.size, args.inheritance);
                if (args.copy != 0) {
                    byte[] data = unicorn.mem_read(args.getSourceAddress(), args.size);
                    unicorn.mem_write(args.target_address, data);
                }

                VmRemapReply reply = new VmRemapReply(request);
                reply.unpack();

                header.msgh_bits &= 0xff;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.retCode = 0;
                reply.target_address1 = (int) args.target_address;
                reply.target_address2 = (int) (args.target_address >> 32);
                reply.cur_protection = args.inheritance;
                reply.max_protection = args.inheritance;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("_kernelrpc_mach_vm_remap reply=" + reply + ", header=" + header);
                }
                return MACH_MSG_SUCCESS;
            }
            case 404: { // vproc_mig_look_up2
                VprocMigLookupRequest args = new VprocMigLookupRequest(request);
                args.unpack();

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
                if (log.isDebugEnabled()) {
                    log.debug("vproc_mig_look_up2 args=" + args + ", data=" + data);
                }

                data.size = 0x20;
                Arrays.fill(data.au_tok.val, 0);
                data.pack();

                if (log.isDebugEnabled()) {
                    log.debug("vproc_mig_look_up2 reply=" + reply + ", data=" + data);
                }
                return MACH_MSG_SUCCESS;
            }
            case 78945669: { // notify_server_register_plain
                NotifyServerRegisterPlainRequest args = new NotifyServerRegisterPlainRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    Pointer pointer = UnicornPointer.pointer(emulator, args.name);
                    log.debug("notify_server_register_plain args=" + args + ", name=" + (pointer == null ? null : new String(pointer.getByteArray(0, args.nameCnt), StandardCharsets.UTF_8)));
                }

                NotifyServerRegisterPlainReply reply = new NotifyServerRegisterPlainReply(request);
                reply.unpack();

                header.msgh_bits &= 0xff;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.ret = 0;
                reply.code = 0;
                reply.clientId = STATIC_PORT;
                reply.status = NOTIFY_STATUS_OK;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("notify_server_register_plain reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 78945681: { // notify_server_get_state
                NotifyServerGetStateRequest args = new NotifyServerGetStateRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("notify_server_get_state args=" + args);
                }

                NotifyServerGetStateReply reply = new NotifyServerGetStateReply(request);
                reply.unpack();

                header.msgh_bits &= 0xff;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.ret = 0;
                reply.code = 0;
                reply.version = 0;
                reply.pid = emulator.getPid();
                reply.status = NOTIFY_STATUS_OK;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("notify_server_get_state reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 78945679: { // notify_server_cancel
                NotifyServerCancelRequest args = new NotifyServerCancelRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("notify_server_cancel args=" + args);
                }

                NotifyServerCancelReply reply = new NotifyServerCancelReply(request);
                reply.unpack();

                header.msgh_bits &= 0xff;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.ret = 0;
                reply.code = 0;
                reply.status = NOTIFY_STATUS_OK;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("notify_server_cancel reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 78945670: { // notify_server_register_check
                NotifyServerRegisterCheckRequest args = new NotifyServerRegisterCheckRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    Pointer pointer = UnicornPointer.pointer(emulator, args.name);
                    log.debug("notify_server_register_check args=" + args + ", name=" + (pointer == null ? null : new String(pointer.getByteArray(0, args.namelen), StandardCharsets.UTF_8)));
                }

                NotifyServerRegisterCheckReply reply = new NotifyServerRegisterCheckReply(request);
                reply.unpack();

                header.msgh_bits &= 0xff;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.ret = 0;
                reply.code = 0;
                reply.shmsize = 0;
                reply.slot = 0;
                reply.clientId = STATIC_PORT;
                reply.status = NOTIFY_STATUS_OK;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("notify_server_register_check reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 118: { // asl_server_message
                AslServerMessageRequest args = new AslServerMessageRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("asl_server_message args=" + args);
                }
                return MACH_MSG_SUCCESS;
            }
            case 78945673: { // notify_server_register_mach_port
                NotifyServerRegisterMachPortRequest args = new NotifyServerRegisterMachPortRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    Pointer pointer = UnicornPointer.pointer(emulator, args.name);
                    log.debug("notify_server_register_mach_port args=" + args + ", name=" + (pointer == null ? null : new String(pointer.getByteArray(0, args.namelen), StandardCharsets.UTF_8)));
                }

                NotifyServerRegisterMachPortReply reply = new NotifyServerRegisterMachPortReply(request);
                reply.unpack();

                header.msgh_bits &= 0xff;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.ret = 0;
                reply.code = 0;
                reply.clientId = STATIC_PORT;
                reply.status = NOTIFY_STATUS_OK;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("notify_server_register_mach_port reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 205: { // host_get_io_master
                MachPortReply reply = new MachPortReply(request);
                reply.unpack();

                header.setMsgBits(true);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.port.name = STATIC_PORT;
                reply.port.pad1 = 0;
                reply.port.pad2 = 0;
                reply.port.disposition = 17;
                reply.port.type = MACH_MSG_PORT_DESCRIPTOR;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("host_get_io_master reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 2873: { // io_service_get_matching_service
                IOServiceGetMatchingServiceRequest args = new IOServiceGetMatchingServiceRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("io_service_get_matching_service args=" + args + ", matching=" + args.getMatching());
                }

                MachPortReply reply = new MachPortReply(request);
                reply.unpack();

                header.setMsgBits(true);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.port.name = STATIC_PORT;
                reply.port.pad1 = 0;
                reply.port.pad2 = 0;
                reply.port.disposition = 17;
                reply.port.type = MACH_MSG_PORT_DESCRIPTOR;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("io_service_get_matching_service reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3405: { // task_info
                TaskInfoRequest args = new TaskInfoRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("task_info args=" + args);
                }

                if (args.flavor == TaskInfoRequest.TASK_DYLD_INFO) {
                    TaskInfoReply reply = new TaskInfoReply(request);
                    reply.unpack();

                    header.setMsgBits(false);
                    header.msgh_size = header.size() + reply.size();
                    header.msgh_remote_port = header.msgh_local_port;
                    header.msgh_local_port = 0;
                    header.msgh_id += 100; // reply Id always equals reqId+100
                    header.pack();

                    reply.retCode = 0;
                    reply.task_info_outCnt = UnicornStructure.calculateSize(TaskDyldInfo.class) / 4;
                    reply.dyldInfo.allocateAllImage(emulator);
                    reply.pack();

                    if (log.isDebugEnabled()) {
                        log.debug("task_info TASK_DYLD_INFO reply=" + reply);
                    }
                    return MACH_MSG_SUCCESS;
                }
            }
            default:
                log.warn("mach_msg_trap header=" + header + ", size=" + header.size() + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                Log log = LogFactory.getLog("com.github.unidbg.AbstractEmulator");
                if (log.isDebugEnabled()) {
                    emulator.attach().debug();
                }
                break;
        }

        return -1;
    }

    private static final int BOOTSTRAP_PORT = 11;
    private static final int CLOCK_SERVER_PORT = 13;
    private static final int SEMAPHORE_PORT = 14;
    private static final int STATIC_PORT = 0x88;

    private int task_self_trap() {
        log.debug("task_self_trap");
        return 1;
    }

    private int host_self_trap() {
        log.debug("host_self_trap");
        return 2;
    }

    private int thread_self_trap() {
        log.debug("thread_self_trap");
        return 3;
    }

    private int mach_reply_port() {
        log.debug("mach_reply_port");
        return 4;
    }

    private int audit_session_self() {
        log.debug("audit_session_self");
        return 5;
    }

    private int sigprocmask(Unicorn u, Emulator<?> emulator) {
        int how = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer set = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oldset = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        return sigprocmask(emulator, how, set, oldset);
    }

    private int gettimeofday(Emulator<?> emulator) {
        EditableArm32RegisterContext context = emulator.getContext();
        long currentTimeMillis = System.currentTimeMillis();
        long tv_sec = currentTimeMillis / 1000;
        long tv_usec = (currentTimeMillis % 1000) * 1000;
        context.setR1((int) tv_usec);
        if (log.isDebugEnabled()) {
            log.debug("gettimeofday");
        }
        return (int) tv_sec;
    }

    private int mach_absolute_time(Emulator<?> emulator) {
        long nanoTime = System.nanoTime();
        if (log.isDebugEnabled()) {
            log.debug("mach_absolute_time nanoTime=" + nanoTime);
        }
        emulator.getUnicorn().reg_write(ArmConst.UC_ARM_REG_R1, (int) (nanoTime >> 32));
        return (int) (nanoTime);
    }

    private int close_NOCANCEL(Emulator<?> emulator) {
        Unicorn u = emulator.getUnicorn();
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("close_NOCANCEL fd=" + fd);
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

    private int read_NOCANCEL(Emulator<?> emulator) {
        Unicorn u = emulator.getUnicorn();
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("read_NOCANCEL fd=" + fd + ", buffer=" + buffer + ", count=" + count);
        }
        return read(emulator, fd, buffer, count);
    }

    private int open_NOCANCEL(Emulator<DarwinFileIO> emulator) {
        Unicorn u = emulator.getUnicorn();
        Pointer pathname_p = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int oflags = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int mode = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        String pathname = pathname_p.getString(0);
        int fd = open(emulator, pathname, oflags);
        if (fd == -1) {
            log.info("open_NOCANCEL pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=0x" + Integer.toHexString(mode));
        } else if (log.isDebugEnabled()) {
            log.debug("open_NOCANCEL pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=0x" + Integer.toHexString(mode) + ", fd=" + fd);
        }
        return fd;
    }

    private int shm_open(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pointer = context.getPointerArg(0);
        int oflags = context.getIntArg(1);
        int mode = context.getIntArg(2);
        String name = pointer.getString(0);
        log.info("shm_open name=" + name + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode));
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int getpid(Emulator<?> emulator) {
        int pid = emulator.getPid();
        log.debug("getpid pid=" + pid);
        return pid;
    }

    private int sendto(Unicorn u, Emulator<?> emulator) {
        int sockfd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int len = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int flags = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        Pointer dest_addr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        int addrlen = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R5)).intValue();

        return sendto(emulator, sockfd, buf, len, flags, dest_addr, addrlen);
    }

    private int connect(Unicorn u, Emulator<?> emulator) {
        int sockfd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer addr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int addrlen = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        return connect(emulator, sockfd, addr, addrlen);
    }

    private int sigaction(Unicorn u, Emulator<?> emulator) {
        int signum = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer act = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oldact = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);

        return sigaction(signum, act, oldact);
    }

    private int fcntl(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int cmd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int arg = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        return fcntl(emulator, fd, cmd, arg);
    }

    @Override
    protected int fcntl(Emulator<?> emulator, int fd, int cmd, long arg) {
        FileIO file = fdMap.get(fd);
        if (file != null && cmd == MachO.F_GETPATH) {
            Pointer pointer = UnicornPointer.pointer(emulator, arg & 0xffffffffL);
            assert pointer != null;
            pointer.setString(0, file.getPath());
            return 0;
        }

        return super.fcntl(emulator, fd, cmd, arg);
    }

    private int mmap(Unicorn u, Emulator<?> emulator) {
        UnicornPointer addr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int length = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int prot = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int flags = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        int r5 = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R5)).intValue();
        long r6 = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R6)).intValue();
        long offset = r5 | (r6 << 32);

        int tag = fd >>> 24;
        if (tag != 0) {
            fd = -1;
        }

        boolean warning = length >= 0x10000000;
        long base = emulator.getMemory().mmap2(addr == null ? 0 : addr.peer, length, prot, flags, fd, (int) offset);
        String msg = "mmap addr=" + addr + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset + ", tag=" + tag;
        if (log.isDebugEnabled() || warning) {
            if (warning) {
                log.warn(msg);
            } else {
                log.debug(msg);
            }
        } else {
            Log log = LogFactory.getLog("com.github.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug(msg + ", base=0x" + Long.toHexString(base));
            }
        }
        return (int) base;
    }

    private int socket(Unicorn u, Emulator<?> emulator) {
        int domain = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int type = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue() & 0x7ffff;
        int protocol = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
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
                if (type == SocketIO.SOCK_DGRAM) {
                    fd = getMinFd();
                    fdMap.put(fd, new LocalDarwinUdpSocket(emulator));
                    return fd;
                }
                emulator.getMemory().setErrno(UnixEmulator.EACCES);
                return -1;
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

    private int write(Unicorn u, Emulator<?> emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        byte[] data = buffer.getByteArray(0, count);
        if (log.isDebugEnabled()) {
            log.debug("write fd=" + fd + ", buffer=" + buffer + ", count=" + count);
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.write(data);
    }

    private int mprotect(Unicorn u, Emulator<?> emulator) {
        long address = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue() & 0xffffffffL;
        long length = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int prot = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        long alignedAddress = address / ARMEmulator.PAGE_ALIGN * ARMEmulator.PAGE_ALIGN; // >> 12 << 12;
        long offset = address - alignedAddress;

        long alignedLength = ARM.alignSize(length + offset, emulator.getPageAlign());
        if (log.isDebugEnabled()) {
            log.debug("mprotect address=0x" + Long.toHexString(address) + ", alignedAddress=0x" + Long.toHexString(alignedAddress) + ", offset=" + offset + ", length=" + length + ", alignedLength=" + alignedLength + ", prot=0x" + Integer.toHexString(prot));
        }
        return emulator.getMemory().mprotect(alignedAddress, (int) alignedLength, prot);
    }

    @Override
    protected DarwinFileIO createByteArrayFileIO(String pathname, int oflags, byte[] data) {
        return new ByteArrayFileIO(oflags, pathname, data);
    }

    @Override
    protected DarwinFileIO createDriverFileIO(Emulator<?> emulator, int oflags, String pathname) {
        return DriverFileIO.create(emulator, oflags, pathname);
    }
}
