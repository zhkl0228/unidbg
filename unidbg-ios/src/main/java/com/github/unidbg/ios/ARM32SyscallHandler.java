package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LongJumpException;
import com.github.unidbg.StopEmulatorException;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.ThumbSvc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.file.ios.IOConstants;
import com.github.unidbg.ios.file.ByteArrayFileIO;
import com.github.unidbg.ios.file.DriverFileIO;
import com.github.unidbg.ios.file.LocalDarwinUdpSocket;
import com.github.unidbg.ios.file.SocketIO;
import com.github.unidbg.ios.file.TcpSocket;
import com.github.unidbg.ios.file.UdpSocket;
import com.github.unidbg.ios.struct.attr.AttrList;
import com.github.unidbg.ios.struct.kernel.AslServerMessageRequest;
import com.github.unidbg.ios.struct.kernel.ClockGetTimeReply;
import com.github.unidbg.ios.struct.kernel.HostGetClockServiceReply;
import com.github.unidbg.ios.struct.kernel.HostGetClockServiceRequest;
import com.github.unidbg.ios.struct.kernel.HostInfoReply;
import com.github.unidbg.ios.struct.kernel.HostInfoRequest;
import com.github.unidbg.ios.struct.kernel.HostRequestNotificationReply;
import com.github.unidbg.ios.struct.kernel.HostRequestNotificationRequest;
import com.github.unidbg.ios.struct.kernel.IOServiceGetMatchingServiceRequest;
import com.github.unidbg.ios.struct.kernel.MachMsgHeader;
import com.github.unidbg.ios.struct.kernel.MachPortOptions;
import com.github.unidbg.ios.struct.kernel.MachPortReply;
import com.github.unidbg.ios.struct.kernel.MachPortSetAttributesReply;
import com.github.unidbg.ios.struct.kernel.MachPortSetAttributesRequest;
import com.github.unidbg.ios.struct.kernel.MachPortsLookupReply32;
import com.github.unidbg.ios.struct.kernel.MachTimebaseInfo;
import com.github.unidbg.ios.struct.kernel.NotifyServerCancelReply;
import com.github.unidbg.ios.struct.kernel.NotifyServerCancelRequest;
import com.github.unidbg.ios.struct.kernel.NotifyServerGetStateReply;
import com.github.unidbg.ios.struct.kernel.NotifyServerGetStateRequest;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterCheckReply;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterCheckRequest;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterMachPortReply;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterMachPortRequest;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterPlainReply;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterPlainRequest;
import com.github.unidbg.ios.struct.kernel.ProcBsdShortInfo;
import com.github.unidbg.ios.struct.kernel.Pthread;
import com.github.unidbg.ios.struct.kernel.Pthread32;
import com.github.unidbg.ios.struct.kernel.RLimit;
import com.github.unidbg.ios.struct.kernel.SemaphoreCreateReply;
import com.github.unidbg.ios.struct.kernel.SemaphoreCreateRequest;
import com.github.unidbg.ios.struct.kernel.Stat;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.ios.struct.kernel.TaskDyldInfoReply;
import com.github.unidbg.ios.struct.kernel.TaskGetExceptionPortsReply;
import com.github.unidbg.ios.struct.kernel.TaskGetExceptionPortsRequest;
import com.github.unidbg.ios.struct.kernel.TaskGetSpecialPortReply;
import com.github.unidbg.ios.struct.kernel.TaskGetSpecialPortRequest;
import com.github.unidbg.ios.struct.kernel.TaskInfoRequest;
import com.github.unidbg.ios.struct.kernel.TaskSetExceptionPortsReply;
import com.github.unidbg.ios.struct.kernel.TaskSetExceptionPortsRequest;
import com.github.unidbg.ios.struct.kernel.ThreadBasicInfoReply;
import com.github.unidbg.ios.struct.kernel.ThreadInfoRequest;
import com.github.unidbg.ios.struct.kernel.ThreadStateReply32;
import com.github.unidbg.ios.struct.kernel.ThreadStateRequest;
import com.github.unidbg.ios.struct.kernel.VmCopyReply;
import com.github.unidbg.ios.struct.kernel.VmCopyRequest;
import com.github.unidbg.ios.struct.kernel.VmRegionRecurse32Reply;
import com.github.unidbg.ios.struct.kernel.VmRegionRecurse32Request;
import com.github.unidbg.ios.struct.kernel.VmRegionReply;
import com.github.unidbg.ios.struct.kernel.VmRegionRequest;
import com.github.unidbg.ios.struct.kernel.VmRemapReply;
import com.github.unidbg.ios.struct.kernel.VmRemapRequest;
import com.github.unidbg.ios.struct.sysctl.IfMsgHeader;
import com.github.unidbg.ios.struct.sysctl.KInfoProc32;
import com.github.unidbg.ios.struct.sysctl.SockAddrDL;
import com.github.unidbg.ios.struct.sysctl.TaskDyldInfo;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.thread.PopContextException;
import com.github.unidbg.thread.RunnableTask;
import com.github.unidbg.thread.Task;
import com.github.unidbg.thread.ThreadContextSwitchException;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.struct.TimeSpec;
import com.github.unidbg.unix.struct.TimeVal32;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.ArmConst;
import unicorn.UnicornConst;

import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import static com.github.unidbg.ios.MachO.MAP_MY_FIXED;
import static com.github.unidbg.ios.file.SocketIO.AF_LINK;
import static com.github.unidbg.ios.file.SocketIO.AF_ROUTE;

/**
 * <a href="http://androidxref.com/4.4.4_r1/xref/external/kernel-headers/original/asm-arm/unistd.h">unistd</a>
 */
public class ARM32SyscallHandler extends DarwinSyscallHandler {

    private static final Logger log = LoggerFactory.getLogger(ARM32SyscallHandler.class);

    private final SvcMemory svcMemory;

    protected ARM32SyscallHandler(SvcMemory svcMemory) {
        super();

        this.svcMemory = svcMemory;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void hook(Backend backend, int intno, int swi, Object user) {
        Emulator<DarwinFileIO> emulator = (Emulator<DarwinFileIO>) user;
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
        if (intno == ARMEmulator.EXCP_UDEF) {
            createBreaker(emulator).debug();
            return;
        }

        if (intno != ARMEmulator.EXCP_SWI) {
            throw new BackendException("intno=" + intno);
        }

        int NR = backend.reg_read(ArmConst.UC_ARM_REG_R12).intValue();
        String syscall = null;
        Throwable exception = null;
        try {
            if (swi == 0 && (backend.reg_read(ArmConst.UC_ARM_REG_R5).intValue()) == Svc.POST_CALLBACK_SYSCALL_NUMBER && (backend.reg_read(ArmConst.UC_ARM_REG_R7).intValue()) == 0) { // postCallback
                int number = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handlePostCallback(emulator);
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi);
            }
            if (swi == 0 && (backend.reg_read(ArmConst.UC_ARM_REG_R5).intValue()) == Svc.PRE_CALLBACK_SYSCALL_NUMBER && (backend.reg_read(ArmConst.UC_ARM_REG_R7).intValue()) == 0) { // preCallback
                int number = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handlePreCallback(emulator);
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi);
            }
            if (swi != DARWIN_SWI_SYSCALL) {
                if (swi == (ARM.isThumb(backend) ? ThumbSvc.SVC_MAX : ArmSvc.SVC_MAX)) {
                    throw new PopContextException();
                }
                if (swi == (ARM.isThumb(backend) ? ThumbSvc.SVC_MAX : ArmSvc.SVC_MAX) - 1) {
                    throw new ThreadContextSwitchException();
                }
                Svc svc = svcMemory.getSvc(swi);
                if (svc != null) {
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, (int) svc.handle(emulator));
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi + ", NR=" + NR);
            }

            if (log.isTraceEnabled()) {
                ARM.showThumbRegs(emulator);
            }

            Cpsr.getArm(backend).setCarry(false);
            if (handleSyscall(emulator, NR)) {
                return;
            }

            switch (NR) {
                case -3:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mach_absolute_time(emulator));
                    return;
                case -10:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_vm_allocate_trap(emulator));
                    return;
                case -12:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_vm_deallocate_trap(emulator));
                    return;
                case -15:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_vm_map_trap(emulator));
                    return;
                case -16:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_allocate_trap(emulator));
                    return;
                case -18:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_deallocate_trap(emulator));
                    return;
                case -19:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_mod_refs_trap(emulator));
                    return;
                case -20:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_move_member_trap(emulator));
                    return;
                case -21:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_insert_right_trap(emulator));
                    return;
                case -22: // _mach_port_insert_member
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _mach_port_insert_member(emulator));
                    return;
                case -24:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_construct_trap(emulator));
                    return;
                case -26: // mach_port_t mach_reply_port(...)
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mach_reply_port());
                    return;
                case -27:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, thread_self_trap());
                    return;
                case -28: // mach_port_name_t task_self_trap(void)
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, task_self_trap());
                    return;
                case -29:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, host_self_trap());
                    return;
                case -31:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mach_msg_trap(emulator));
                    return;
                case -33: // _semaphore_signal_trap
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _semaphore_signal_trap(emulator));
                    return;
                case -36: // _semaphore_wait_trap
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _semaphore_wait_trap(emulator));
                    return;
                case -41: // _xpc_mach_port_guard
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_guard_trap(emulator));
                    return;
                case -59: // swtch_pri
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, swtch_pri(emulator));
                    return;
                case -61:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, thread_switch(emulator));
                    return;
                case -89:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _mach_timebase_info(emulator));
                    return;
                case -91: // mk_timer_create
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _mk_timer_create());
                    return;
                case -93: // mk_timer_arm
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _mk_timer_arm(emulator));
                    return;
                case 1:
                    exit(emulator);
                    return;
                case 4:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, write(emulator));
                    return;
                case 6:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, close(emulator));
                    return;
                case 10:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, unlink(emulator));
                    return;
                case 15:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, chmod(emulator));
                    return;
                case 16:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, chown(emulator));
                    return;
                case 20:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getpid(emulator));
                    return;
                case 24: // getuid
                case 25: // geteuid
                case 43: // getegid
                case 47: // getgid
                    if (log.isDebugEnabled()) {
                        log.debug("NR={}", NR);
                    }
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, 0);
                    return;
                case 33:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, access(emulator));
                    return;
                case 34:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, chflags(emulator));
                    return;
                case 37:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, kill(emulator));
                    return;
                case 39:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getppid(emulator));
                    return;
                case 46:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sigaction(emulator));
                    return;
                case 48:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sigprocmask(emulator));
                    return;
                case 52:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sigpending(emulator));
                    return;
                case 53:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sigaltstack(emulator));
                    return;
                case 54:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, ioctl(emulator));
                    return;
                case 58:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, readlink(emulator));
                    return;
                case 73:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, munmap(emulator));
                    return;
                case 74:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mprotect(emulator));
                    return;
                case 75:
                    syscall = "posix_madvise";
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, 0);
                    return;
                case 92:
                case 406: // fcntl_NOCANCEL
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fcntl(emulator));
                    return;
                case 95:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fsync(emulator));
                    return;
                case 97:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, socket(emulator));
                    return;
                case 98:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, connect(emulator));
                    return;
                case 116:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, gettimeofday(emulator));
                    return;
                case 121:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, writev(emulator));
                    return;
                case 128:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, rename(emulator));
                    return;
                case 133:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sendto(emulator));
                    return;
                case 136:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mkdir(emulator));
                    return;
                case 137:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, rmdir(emulator));
                    return;
                case 194:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getrlimit(emulator));
                    return;
                case 197:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, mmap(emulator));
                    return;
                case 199:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, lseek(emulator));
                    return;
                case 201:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, ftruncate(emulator));
                    return;
                case 202:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sysctl(emulator));
                    return;
                case 216:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, open_dprotected_np(emulator));
                    return;
                case 220:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getattrlist(emulator));
                    return;
                case 221:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, setattrlist(emulator));
                    return;
                case 240:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, listxattr(emulator));
                    return;
                case 236:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, setxattr(emulator));
                    return;
                case 237:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fsetxattr(emulator));
                    return;
                case 286:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, pthread_getugid_np(emulator));
                    return;
                case 301:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, psynch_mutexwait(emulator));
                    return;
                case 302:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, psynch_mutexdrop(emulator));
                    return;
                case 303:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, psynch_cvbroad(emulator));
                    return;
                case 305:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, psynch_cvwait(emulator));
                    return;
                case 327:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, issetugid());
                    return;
                case 328:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, pthread_kill(emulator));
                    return;
                case 329:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, pthread_sigmask(emulator));
                    return;
                case 330:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sigwait(emulator));
                    return;
                case 331:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, disable_threadsignal(emulator));
                    return;
                case 334:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, semwait_signal(emulator));
                    return;
                case 336:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, proc_info(emulator));
                    return;
                case 338:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, stat64(emulator));
                    return;
                case 339:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fstat(emulator));
                    return;
                case 340:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, lstat(emulator));
                    return;
                case 344:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getdirentries64(emulator));
                    return;
                case 345:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, statfs64(emulator));
                    return;
                case 346:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, fstatfs64(emulator));
                    return;
                case 347:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getfsstat64(emulator, 0));
                    return;
                case 357:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, getaudit_addr(emulator));
                    return;
                case 360:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, bsdthread_create(emulator));
                    return;
                case 361:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, bsdthread_terminate(emulator));
                    return;
                case 362:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, kqueue());
                    return;
                case 366:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, bsdthread_register(emulator));
                    return;
                case 367:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _workq_open());
                    return;
                case 368:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, _workq_kernreturn());
                    return;
                case 369:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, kevent64(emulator));
                    return;
                case 372:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, thread_selfid(emulator));
                    backend.reg_write(ArmConst.UC_ARM_REG_R1, 0);
                    return;
                case 381:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, sandbox_ms(emulator));
                    return;
                case 3:
                case 396:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, read_NOCANCEL(emulator));
                    return;
                case 397:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, write_NOCANCEL(emulator));
                    return;
                case 5: // unix open
                case 398:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, open_NOCANCEL(emulator, 0));
                    return;
                case 266:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, shm_open(emulator));
                    return;
                case 399:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, close_NOCANCEL(emulator));
                    return;
                case 423:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, semwait_signal(emulator));
                    return;
                case 428:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, audit_session_self());
                    return;
                case 443:
                    backend.reg_write(ArmConst.UC_ARM_REG_R0, guarded_kqueue_np(emulator));
                    return;
                case 0x80000000:
                    NR = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
                    if(handleMachineDependentSyscall(emulator, NR)) {
                        return;
                    }
                default:
                    break;
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

        log.warn("handleInterrupt intno={}, NR={}, svcNumber=0x{}, PC={}, syscall={}", intno, NR, Integer.toHexString(swi), pc, syscall, exception);
        if (log.isDebugEnabled() || LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            createBreaker(emulator).debug();
        }

        if (exception instanceof RuntimeException) {
            throw (RuntimeException) exception;
        }
    }

    private int _kernelrpc_mach_port_move_member_trap(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int task = context.getIntArg(0);
        int member = context.getIntArg(1);
        int after = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_move_member_trap task={}, member={}, after={}", task, member, after);
        }
        return 0;
    }

    private int chflags(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        int flags = context.getIntArg(1);
        String pathname = path.getString(0);
        log.info("chflags paht={}, flags=0x{}", pathname, Integer.toHexString(flags));
        return -1;
    }

    private int open_dprotected_np(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        int flags = context.getIntArg(1);
        int _class = context.getIntArg(2);
        int dpflags = context.getIntArg(3);
        String pathname = path.getString(0);
        log.info("open_dprotected_np path={}, flags=0x{}, class={}, dpflags=0x{}", pathname, Integer.toHexString(flags), _class, Integer.toHexString(dpflags));
        return -1;
    }

    private int fsetxattr(Emulator<DarwinFileIO> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer name = context.getPointerArg(1);
        Pointer value = context.getPointerArg(2);
        int size = context.getIntArg(3);
        int position = context.getR4Int();
        int options = context.getR5Int();
        log.info("fsetxattr fd={}, name={}, value={}, size={}, position={}, options=0x{}", fd, name.getString(0), value, size, position, Integer.toHexString(options));
        return -1;
    }

    private int setxattr(Emulator<DarwinFileIO> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        Pointer name = context.getPointerArg(1);
        Pointer value = context.getPointerArg(2);
        int size = context.getIntArg(3);
        int position = context.getR4Int();
        int options = context.getR5Int();
        log.info("setxattr pat={}, name={}, value={}, size={}, position={}, options=0x{}", path.getString(0), name.getString(0), value, size, position, Integer.toHexString(options));
        return -1;
    }

    private int getattrlist(Emulator<DarwinFileIO> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        Pointer attrListPointer = context.getPointerArg(1);
        UnidbgPointer attrBuf = context.getPointerArg(2);
        int attrBufSize = context.getIntArg(3);
        int options = context.getR4Int();
        String pathname = path.getString(0);
        AttrList attrList = new AttrList(attrListPointer);
        attrBuf.setSize(attrBufSize);

        String msg = "getattrlist path=" + pathname + ", attrList=" + attrList + ", attrBuf=" + attrBuf + ", attrBufSize=" + attrBufSize + ", options=0x" + Integer.toHexString(options);
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            int ret = result.io.getattrlist(attrList, attrBuf, attrBufSize);
            if (ret != 0) {
                log.info("{}, ret={}", msg, ret);
            } else {
                log.debug("{}", msg);
            }
            return ret;
        }

        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.EACCES);
        log.info(msg);
        return -1;
    }

    private int setattrlist(Emulator<DarwinFileIO> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        Pointer attrListPointer = context.getPointerArg(1);
        UnidbgPointer attrBuf = context.getPointerArg(2);
        int attrBufSize = context.getIntArg(3);
        int options = context.getR4Int();
        String pathname = path.getString(0);
        AttrList attrList = new AttrList(attrListPointer);
        attrBuf.setSize(attrBufSize);

        String msg = String.format("path=%s, attrList=%s, attrBuf=%s, attrBufSize=%d, options=0x%s", pathname, attrList, attrBuf, attrBufSize, Integer.toHexString(options));
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            int ret = result.io.setattrlist(attrList, attrBuf, attrBufSize);
            if (ret != 0) {
                log.info("{} {}, ret={}", "setattrlist", msg, ret);
            } else {
                log.debug("{}", msg);
            }
            return ret;
        }

        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.EACCES);
        log.info(msg);
        return -1;
    }

    private int fsync(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("fsync fd={}", fd);
        }
        return 0;
    }

    private int sigaltstack(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer nstack = context.getPointerArg(0);
        Pointer ostack = context.getPointerArg(1);
        log.info("sigaltstack nstack={}, ostack={}", nstack, ostack);
        return 0;
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

    private boolean handleMachineDependentSyscall(Emulator<?> emulator, int NR) {
        Backend backend = emulator.getBackend();
        switch (NR) {
            case 0:
                backend.reg_write(ArmConst.UC_ARM_REG_R0, sys_icache_invalidate(emulator));
                return true;
            case 1:
                backend.reg_write(ArmConst.UC_ARM_REG_R0, sys_dcache_flush(emulator));
                return true;
            case 2:
                backend.reg_write(ArmConst.UC_ARM_REG_R0, pthread_set_self(emulator));
                return true;
        }
        return false;
    }

    private int pthread_set_self(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer self = context.getPointerArg(0);
        Pthread pthread = new Pthread32(self.getPointer(0));
        pthread.unpack();
        UnidbgPointer tsd = pthread.getTSD();
        emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tsd.peer);

        Task task = emulator.get(Task.TASK_KEY);
        if (task != null && task.isMainThread()) {
            MachOLoader loader = (MachOLoader) emulator.getMemory();
            loader.setErrnoPointer(pthread.getErrno());
        }

        if (log.isDebugEnabled()) {
            String threadName = pthread.getName();
            log.debug("pthread_set_self={}, pthread={}, threadName={}, LR={}", self, pthread, threadName, emulator.getContext().getLRPointer());
        }
        return 0;
    }

    private int sys_dcache_flush(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer address = context.getPointerArg(0);
        long size = context.getLongArg(1);
        if (log.isDebugEnabled()) {
            log.debug("sys_dcache_flush address={}, size={}", address, size);
        }
        return 0;
    }

    private int sys_icache_invalidate(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer address = context.getPointerArg(0);
        long size = context.getLongArg(1);
        if (log.isDebugEnabled()) {
            log.debug("sys_icache_invalidate address={}, size={}", address, size);
        }
        return 0;
    }

    private int pthread_getugid_np(Emulator<?> emulator) {
        Pointer uid = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer gid = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        if (log.isDebugEnabled()) {
            log.debug("pthread_getugid_np uid={}, gid={}", uid, gid);
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
            log.debug("_mach_timebase_info info={}, LR={}", info, context.getLRPointer());
        }
        return 0;
    }

    private int _mk_timer_create() {
        if (log.isDebugEnabled()) {
            log.debug("_mk_timer_create");
        }
        return STATIC_PORT;
    }

    private int _mk_timer_arm(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int port = context.getIntArg(0);
        long time = context.getLongArg(1);
        if (log.isDebugEnabled()) {
            log.debug("_mk_timer_arm port={}, time={}", port, time);
        }
        return 0;
    }

    private int readlink(Emulator<?> emulator) {
        Backend emulatorBackend = emulator.getBackend();
        Pointer pathname = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer buf = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int bufSize = emulatorBackend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        String path = pathname.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("readlink path={}, buf={}, bufSize={}", path, buf, bufSize);
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
            log.debug("psynch_mutexdrop mutex={}, mgen={}, ugen={}, tid={}, flags=0x{}, LR={}", mutex, mgen, ugen, tid, Integer.toHexString(flags), context.getLRPointer());
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
            log.debug("psynch_mutexwait mutex={}, mgen={}, ugen={}, tid={}, flags=0x{}, LR={}", mutex, mgen, ugen, tid, Integer.toHexString(flags), context.getLRPointer());
        }
        return 0;
    }

    private int bsdthread_create(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        UnidbgPointer start_routine = context.getPointerArg(0);
        UnidbgPointer arg = context.getPointerArg(1);
        UnidbgPointer stack = context.getPointerArg(2);
        UnidbgPointer thread = context.getPointerArg(3);
        int flags = context.getR4Int();

        return (int) bsdthread_create(emulator, start_routine, arg, stack, thread, flags);
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

    private int kevent64(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        int kq = context.getR0Int();
        Pointer changelist = context.getR1Pointer();
        int nchanges = context.getR2Int();
        Pointer eventlist = context.getR3Pointer();
        int nevents = context.getR4Int();
        int flags = context.getR5Int();
        Pointer timeout = context.getR6Pointer();
        return kevent64(emulator, kq, changelist, nchanges, eventlist, nevents, flags, TimeSpec.createTimeSpec(emulator, timeout));
    }

    private int _kernelrpc_mach_port_allocate_trap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int task = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int right = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        Pointer name = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_allocate_trap task={}, right={}, name={}", task, right, name);
        }
        name.setInt(0, STATIC_PORT);
        return 0;
    }

    private int _kernelrpc_mach_port_insert_right_trap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int task = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int name = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int poly = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int polyPoly = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_insert_right_trap task={}, name={}, poly={}, polyPoly={}", task, name, poly, polyPoly);
        }
        return 0;
    }

    private int _mach_port_insert_member(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int task = context.getIntArg(0);
        int name = context.getIntArg(1);
        int pset = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("_mach_port_insert_member task={}, name={}, pset={}", task, name, pset);
        }
        return 0;
    }

    private int _semaphore_signal_trap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int port = context.getIntArg(0);
        log.info("_semaphore_signal_trap port={}", port);
        if (log.isDebugEnabled() || LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            createBreaker(emulator).debug();
        }
        return 0;
    }

    private long _kernelrpc_mach_port_guard_trap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int task = context.getIntArg(0);
        int name = context.getIntArg(1);
        Pointer guard = context.getPointerArg(2);
        int strict = context.getIntArg(3);
        log.info("_kernelrpc_mach_port_guard_trap task={}, name={}, guard={}, strict={}", task, name, guard, strict);
        return 0;
    }

    private int thread_switch(Emulator<?> emulator) {
        // TODO: implement
        RegisterContext context = emulator.getContext();
        int thread_name = context.getIntArg(0);
        int option = context.getIntArg(1);
        int option_time = context.getIntArg(2);
        log.info("thread_switch thread_name={}, option={}, option_time={}", thread_name, option, option_time);
        return 0;
    }

    private int psynch_cvwait(Emulator<?> emulator) {
        if (threadDispatcherEnabled) {
            throw new ThreadContextSwitchException();
        }

        log.info("psynch_cvwait LR={}", emulator.getContext().getLRPointer());
        emulator.attach().debug();
        emulator.getMemory().setErrno(UnixEmulator.EINTR);
        return -1;
    }

    private int close(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("close fd={}", fd);
        }

        return close(emulator, fd);
    }

    private int lseek(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int r1 = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        long r2 = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        long offset = r1 | (r2 << 32);
        int whence = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        FileIO file = fdMap.get(fd);
        if (file == null) {
            if (log.isDebugEnabled()) {
                log.debug("lseek fd={}, offset={}, whence={}", fd, offset, whence);
            }
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int pos = file.lseek((int) offset, whence);
        if (log.isDebugEnabled()) {
            log.debug("lseek fd={}, offset={}, whence={}, pos={}", fd, offset, whence, pos);
        }
        return pos;
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

    private int unlink(Emulator<?> emulator) {
        Pointer pathname = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        String path = FilenameUtils.normalize(pathname.getString(0), true);
        emulator.getFileSystem().unlink(path);
        return 0;
    }

    private int chown(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        int uid = context.getIntArg(1);
        int gid = context.getIntArg(2);
        String pathname = path.getString(0);
        log.info("chown path={}, uid={}, gid={}", pathname, uid, gid);
        return 0;
    }

    private int getdirentries64(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        UnidbgPointer buf = context.getPointerArg(1);
        int bufSize = context.getIntArg(2);
        Pointer basep = context.getPointerArg(3);
        if (log.isDebugEnabled()) {
            log.debug("getdirentries64 fd={}, buf={}, bufSize={}, basep={}, LR={}", fd, buf, bufSize, basep, context.getLRPointer());
        }

        DarwinFileIO io = fdMap.get(fd);
        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        } else {
            buf.setSize(bufSize);
            return io.getdirentries64(buf, bufSize);
        }
    }

    protected int statfs64(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pathPointer = context.getPointerArg(0);
        Pointer buf = context.getPointerArg(1);
        String path = pathPointer.getString(0);
        FileResult<DarwinFileIO> result = resolve(emulator, path, IOConstants.O_RDONLY);
        if (log.isDebugEnabled()) {
            log.debug("statfs64 pathPointer={}, buf={}, path={}", pathPointer, buf, path);
        }
        if (result != null && result.isSuccess()) {
            return result.io.fstatfs(new StatFS(buf));
        }
        log.info("statfs64 pathPointer={}, buf={}, path={}", pathPointer, buf, path);
        throw new BackendException("statfs64 path=" + path + ", buf=" + buf);
    }

    private int fstatfs64(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer buf = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        if (log.isDebugEnabled()) {
            log.debug("fstatfs64 fd={}, buf={}", fd, buf);
        }
        DarwinFileIO io = fdMap.get(fd);
        if (io != null) {
            return io.fstatfs(new StatFS(buf));
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int stat64(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pathname = context.getPointerArg(0);
        Pointer statbuf = context.getPointerArg(1);
        String path = pathname.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("stat64 pathname={}, statbuf={}, LR={}", path, statbuf, context.getLRPointer());
        }
        return stat64(emulator, FilenameUtils.normalize(path, true), statbuf);
    }

    protected int fstat(Emulator<DarwinFileIO> emulator, int fd, Pointer stat) {
        if (log.isDebugEnabled()) {
            log.debug("fstat fd={}, stat={}", fd, stat);
        }

        DarwinFileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        if (log.isDebugEnabled()) {
            log.debug("fstat file={}, stat={}", file, stat);
        }
        return file.fstat(emulator, new Stat(stat));
    }

    protected int stat64(Emulator<DarwinFileIO> emulator, String pathname, Pointer statbuf) {
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            return result.io.fstat(emulator, new Stat(statbuf));
        }

        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.ENOENT);
        return -1;
    }

    private int write_NOCANCEL(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer buffer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        return write(emulator, fd, buffer, count);
    }

    private int fstat(Emulator<DarwinFileIO> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer stat = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        return fstat(emulator, fd, stat);
    }

    /**
     * lstat() is identical to stat(), except that if pathname is a symbolic link, then it returns information about the link itself, not the file that it refers to.
     */
    private int lstat(Emulator<DarwinFileIO> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer pathname = context.getR0Pointer();
        Pointer stat = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        String pathStr = pathname.getString(0);
        String path = FilenameUtils.normalize(pathStr, true);
        if (log.isDebugEnabled()) {
            log.debug("lstat path={}, pathStr={}, stat={}", path, pathStr, stat);
        }
        return stat64(emulator, path, stat);
    }

    private static final int RLIMIT_NOFILE = 8;		/* number of open files */
    private static final int RLIMIT_POSIX_FLAG = 0x1000;	/* Set bits for strict POSIX */

    private int getrlimit(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int resource = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer rlp = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
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
        Backend backend = emulator.getBackend();
        int task = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int name = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int right = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int delta = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_mod_refs_trap task={}, name={}, right={}, delta={}", task, name, right, delta);
        }
        return 0;
    }

    private int _kernelrpc_mach_port_construct_trap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int task = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer options = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int r2 = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        long r3 = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        long context = r2 | (r3 << 32);
        Pointer name = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        if (log.isDebugEnabled()) {
            MachPortOptions portOptions = new MachPortOptions(options);
            portOptions.unpack();
            log.debug("_kernelrpc_mach_port_construct_trap task={}, options={}, context=0x{}, name={}, portOptions={}", task, options, Long.toHexString(context), name, portOptions);
        }
        name.setInt(0, 0x88);
        return 0;
    }

    private int getaudit_addr(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        Pointer addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int size = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        if (log.isDebugEnabled()) {
            log.debug("getaudit_addr={}, size={}", addr, size);
        }
        return 0;
    }

    private int semwait_signal(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        int cond_sem = context.getR0Int();
        int mutex_sem = context.getR1Int();
        int timeout = context.getR2Int();
        int relative = context.getR3Int();
        long tv_sec = context.getR4Int() | (long) context.getR5Int() << 32;
        int tv_nsec = context.getR6Int();
        RunnableTask runningTask = emulator.getThreadDispatcher().getRunningTask();
        String msg = "semwait_signal cond_sem=" + cond_sem + ", mutex_sem=" + mutex_sem + ", timeout=" + timeout + ", relative=" + relative + ", tv_sec=" + tv_sec + ", tv_nsec=" + tv_nsec;
        if (threadDispatcherEnabled && runningTask != null) {
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            return semwait_signal(emulator, runningTask, cond_sem, mutex_sem, timeout, relative, tv_sec, tv_nsec);
        }
        log.info(msg);
        try {
            Thread.sleep(tv_sec * 1000L + tv_nsec / 1000L, tv_nsec % 1000);
            emulator.getMemory().setErrno(ETIMEDOUT);
            return -1;
        } catch (InterruptedException e) {
            emulator.getMemory().setErrno(UnixEmulator.EINVAL);
            return -1;
        }
    }

    private static final int PROC_INFO_CALL_SETCONTROL = 0x5;
    private static final int PROC_SELFSET_THREADNAME = 2;

    private static final int PROC_INFO_CALL_PIDINFO = 0x2;
    private static final int PROC_PIDT_SHORTBSDINFO = 13;

    private int proc_info(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int callNum = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int pid = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int flavor = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int r3 = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        long r4 = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
        long arg = r3 | (r4 << 32);
        Pointer buffer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R5);
        int bufferSize = backend.reg_read(ArmConst.UC_ARM_REG_R6).intValue();

        String msg = "proc_info callNum=" + callNum + ", pid=" + pid + ", flavor=" + flavor + ", arg=" + arg + ", buffer=" + buffer + ", bufferSize=" + bufferSize;
        if (PROC_INFO_CALL_SETCONTROL == callNum && PROC_SELFSET_THREADNAME == flavor) {
            String threadName = buffer.getString(0);
            if (log.isDebugEnabled()) {
                log.debug("{}, threadName={}", msg, threadName);
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
                log.debug("{}, info={}", msg, info);
            }
            return info.size();
        } else {
            log.info(msg);
            return 1;
        }
    }

    private int sandbox_ms(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        Pointer policyName = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int call = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        Pointer args = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        if (log.isDebugEnabled()) {
            log.debug("sandbox_ms policyName={}, call={}, args={}", policyName.getString(0), call, args);
        }
        return 0;
    }

    private int issetugid() {
        log.debug("issetugid");
        return 0;
    }

    private int bsdthread_register(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        UnidbgPointer thread_start = context.getR0Pointer();
        UnidbgPointer start_wqthread = context.getR1Pointer();
        int pthreadSize = context.getR2Int();
        UnidbgPointer data = context.getR3Pointer();
        int dataSize = context.getR4Int();
        int r5 = context.getR5Int();
        long r6 = context.getR6Int();
        long offset = r5 | (r6 << 32);
        if (log.isDebugEnabled()) {
            log.debug("bsdthread_register thread_start={}, start_wqthread={}, pthreadSize={}, data={}, dataSize={}, offset=0x{}", thread_start, start_wqthread, pthreadSize, data, dataSize, Long.toHexString(offset));
        }
        return bsdthread_register(thread_start, pthreadSize);
    }

    private int munmap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        long timeInMillis = System.currentTimeMillis();
        long start = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue() & 0xffffffffL;
        int length = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        emulator.getMemory().munmap(start, length);
        if (log.isDebugEnabled()) {
            log.debug("munmap start=0x{}, length={}, offset={}", Long.toHexString(start), length, System.currentTimeMillis() - timeInMillis);
        }
        return 0;
    }

    private int sysctl(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        Pointer name = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int namelen = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        Pointer buffer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        Pointer bufferSize = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
        Pointer set0 = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        int set1 = backend.reg_read(ArmConst.UC_ARM_REG_R5).intValue();

        int top = name.getInt(0);
        switch (top) {
            case CTL_UNSPEC: {
                int action = name.getInt(4);
                if (action == 3) {
                    byte[] bytes = set0.getByteArray(0, set1);
                    String sub = new String(bytes, StandardCharsets.UTF_8);
                    if (log.isDebugEnabled()) {
                        log.debug("sysctl CTL_UNSPEC action={}, namelen={}, buffer={}, bufferSize={}, sub={}", action, namelen, buffer, bufferSize, sub);
                    }
                    switch (sub) {
                        case "unidbg.debug":
                            return LoggerFactory.getLogger("com.github.unidbg.ios.debug").isDebugEnabled() ? 1 : 0;
                        case "kern.ostype":
                            buffer.setInt(0, CTL_KERN);
                            buffer.setInt(4, KERN_OSTYPE);
                            bufferSize.setInt(0, 8);
                            return 0;
                        case "kern.osrelease":
                            buffer.setInt(0, CTL_KERN);
                            buffer.setInt(4, KERN_OSRELEASE);
                            bufferSize.setInt(0, 8);
                            return 0;
                        case "kern.version":
                            buffer.setInt(0, CTL_KERN);
                            buffer.setInt(4, KERN_VERSION);
                            bufferSize.setInt(0, 8);
                            return 0;
                        case "kern.osversion":
                            buffer.setInt(0, CTL_KERN);
                            buffer.setInt(4, KERN_OSVERSION);
                            bufferSize.setInt(0, 8);
                            return 0;
                        case "kern.boottime":
                            buffer.setInt(0, CTL_KERN);
                            buffer.setInt(4, KERN_BOOTTIME);
                            bufferSize.setInt(0, 8);
                            return 0;
                        case "hw.machine":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_MACHINE);
                            bufferSize.setInt(0, 8);
                            return 0;
                        case "hw.model":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_MODEL);
                            bufferSize.setInt(0, 8);
                            return 0;
                        case "hw.cputype":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_CPU_TYPE);
                            bufferSize.setInt(0, 8);
                            return 0;
                        case "hw.cpusubtype":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_CPU_SUBTYPE);
                            bufferSize.setInt(0, 8);
                            return 0;
                        case "hw.cpufamily":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_CPU_FAMILY);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "hw.ncpu":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_NCPU);
                            bufferSize.setInt(0, 8);
                            return 0;
                        case "hw.memsize":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_MEMSIZE);
                            bufferSize.setInt(0, 8);
                            return 0;
                    }
                    if (log.isDebugEnabled()) {
                        createBreaker(emulator).debug();
                    }
                    return -1;
                }
                log.info("sysctl CTL_UNSPEC action={}, namelen={}, buffer={}, bufferSize={}, set0={}, set1={}", action, namelen, buffer, bufferSize, set0, set1);
                break;
            }
            case CTL_KERN: {
                int action = name.getInt(4);
                String msg = "sysctl CTL_KERN action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1;
                switch (action) {
                    case KERN_PROCARGS2:
                        log.info(msg);
                        return 1;
                    case KERN_OSTYPE:
                        log.debug(msg);
                        String osType = getKernelOsType();
                        if (bufferSize != null) {
                            bufferSize.setInt(0, osType.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, osType);
                        }
                        return 0;
                    case KERN_OSRELEASE:
                        log.debug(msg);
                        String osRelease = getKernelOsRelease();
                        if (bufferSize != null) {
                            bufferSize.setInt(0, osRelease.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, osRelease);
                        }
                        return 0;
                    case KERN_VERSION:
                        log.debug(msg);
                        String version = getKernelVersion();
                        if (bufferSize != null) {
                            bufferSize.setInt(0, version.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, version);
                        }
                        return 0;
                    case KERN_ARGMAX:
                        bufferSize.setInt(0, 4);
                        buffer.setInt(0, 128);
                        return 0;
                    case KERN_HOSTNAME:
                        log.debug(msg);
                        String host = getKernelHostName();
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

                            kInfoProc.kp_proc.p_flag = 0; // P_TRACED
                            kInfoProc.kp_eproc.e_ucred.cr_uid = 0;
                            kInfoProc.pack();
                            if (log.isDebugEnabled()) {
                                log.debug("{}, subType={}, pid={}, kInfoProc={}", msg, subType, pid, kInfoProc);
                            }
                            return 0;
                        }
                        log.info("{}, subType={}", msg, subType);
                        break;
                    case KERN_OSVERSION:
                        log.debug(msg);
                        String osVersion = getBuildVersion();
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
                    case KERN_BOOTTIME:
                        if (bufferSize != null) {
                            bufferSize.setInt(0, UnidbgStructure.calculateSize(TimeVal32.class));
                        }
                        if (buffer != null) {
                            fillKernelBootTime(buffer);
                        }
                        return 0;
                    default:
                        log.info(msg);
                        break;
                }
                break;
            }
            case CTL_HW: {
                int action = name.getInt(4);
                String msg = "sysctl CTL_HW action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1;
                switch (action) {
                    case HW_CPU_FREQ:
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, 1800000000);
                        }
                        return 0;
                    case HW_PAGESIZE:
                        log.debug(msg);
                        if (bufferSize != null) {
                            bufferSize.setInt(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, emulator.getPageAlign());
                        }
                        return 0;
                    case HW_CPU_TYPE:
                        log.debug(msg);
                        if (bufferSize != null) {
                            bufferSize.setInt(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, CPU_TYPE_ARM);
                        }
                        return 0;
                    case HW_CPU_SUBTYPE:
                        log.debug(msg);
                        if (bufferSize != null) {
                            bufferSize.setInt(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, CPU_SUBTYPE_ARM_V7);
                        }
                        return 0;
                    case HW_CPU_FAMILY:
                        log.debug(msg);
                        if (bufferSize != null) {
                            bufferSize.setInt(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, 933271106);
                        }
                        return 0;
                    case HW_MACHINE:
                        log.debug(msg);
                        String machine = getHwMachine();
                        if (bufferSize != null) {
                            bufferSize.setInt(0, machine.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, machine);
                        }
                        return 0;
                    case HW_MODEL:
                        log.debug(msg);
                        String model = "N53AP";
                        if (bufferSize != null) {
                            bufferSize.setInt(0, model.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, model);
                        }
                        return 0;
                    case HW_NCPU:
                        log.debug(msg);
                        if (bufferSize != null) {
                            bufferSize.setInt(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, getHwNcpu()); // 2 cpus
                        }
                        return 0;
                    case HW_MEMSIZE:
                        if (bufferSize != null) {
                            bufferSize.setInt(0, 8);
                        }
                        if (buffer != null) {
                            long memSize = 2L * 1024 * 1024 * 1024; // 2G
                            buffer.setLong(0, memSize);
                        }
                        return 0;
                }
                log.info(msg);
                break;
            }
            case CTL_NET:
                int action = name.getInt(4); // AF_ROUTE
                String msg = "sysctl CTL_NET action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1;
                int family = name.getInt(0xc); // AF_INET
                int rt = name.getInt(0x10);
                if(action == AF_ROUTE && rt == NET_RT_IFLIST) {
                    try {
                        List<DarwinUtils.NetworkIF> networkIFList = DarwinUtils.getNetworkIFs(isVerbose());
                        int sizeOfSDL = UnidbgStructure.calculateSize(SockAddrDL.class);
                        int entrySize = UnidbgStructure.calculateSize(IfMsgHeader.class) + sizeOfSDL;
                        if (bufferSize != null) {
                            bufferSize.setInt(0, entrySize * networkIFList.size());
                        }
                        if (buffer != null) {
                            Pointer pointer = buffer;
                            short index = 0;
                            for (DarwinUtils.NetworkIF networkIF : networkIFList) {
                                IfMsgHeader header = new IfMsgHeader(pointer);
                                SockAddrDL sockAddr = new SockAddrDL(pointer.share(header.size()));
                                header.ifm_msglen = (short) entrySize;
                                header.ifm_version = 5;
                                header.ifm_type = RTM_IFINFO;
                                header.ifm_addrs = 0x10;
                                header.ifm_index = ++index;
                                header.ifm_data.ifi_type = 6; // ethernet
                                header.pack();
                                byte[] networkInterfaceName = networkIF.networkInterface.getName().getBytes();
                                sockAddr.sdl_len = (byte) sizeOfSDL;
                                sockAddr.sdl_family = AF_LINK;
                                sockAddr.sdl_index = index;
                                sockAddr.sdl_type = 6; // ethernet
                                sockAddr.sdl_nlen = (byte) networkInterfaceName.length;
                                System.arraycopy(networkInterfaceName, 0, sockAddr.sdl_data, 0, networkInterfaceName.length);
                                byte[] macAddress = networkIF.networkInterface.getHardwareAddress();
                                sockAddr.sdl_alen = (byte) macAddress.length;
                                System.arraycopy(macAddress, 0, sockAddr.sdl_data, networkInterfaceName.length, macAddress.length);
                                sockAddr.pack();
                                pointer = pointer.share(entrySize);
                            }
                        }
                        return 0;
                    } catch (SocketException e) {
                        throw new IllegalStateException(e);
                    }
                }
                log.info("{}, family={}, rt={}", msg, family, rt);
                if (log.isDebugEnabled()) {
                    createBreaker(emulator).debug();
                }
            default:
                log.info("sysctl top={}, namelen={}, buffer={}, bufferSize={}, set0={}, set1={}", name.getInt(0), namelen, buffer, bufferSize, set0, set1);
                break;
        }
        return -1;
    }

    private int _kernelrpc_mach_vm_deallocate_trap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int target = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        long r1 = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        long r2 = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        long address = r1 | (r2 << 32);
        long r3 = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        long r4 = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
        long size = r3 | (r4 << 32);

        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_deallocate_trap target={}, address=0x{}, size=0x{}", target, Long.toHexString(address), Long.toHexString(size));
        } else {
            Logger log = LoggerFactory.getLogger("com.github.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug("_kernelrpc_mach_vm_deallocate_trap target=" + target + ", address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", lr=" + UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
            }
        }
        if (size > 0) {
            emulator.getMemory().munmap(address, (int) size);
        }
        return 0;
    }

    @Override
    protected void fillKernelBootTime(Pointer buffer) {
        long currentTimeMillis = bootTime;
        long tv_sec = currentTimeMillis / 1000;
        long tv_usec = (currentTimeMillis % 1000) * 1000 + (bootTime / 7 % 1000);
        TimeVal32 timeVal = new TimeVal32(buffer);
        timeVal.tv_sec = (int) tv_sec;
        timeVal.tv_usec = (int) tv_usec;
        timeVal.pack();
    }

    private int _kernelrpc_mach_vm_map_trap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int target = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer address = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int r2 = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        long r3 = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        long size = (r3 << 32) | r2;
        int r4 = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
        long r5 = backend.reg_read(ArmConst.UC_ARM_REG_R5).intValue();
        long mask = (r5 << 32) | r4;
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R6).intValue();
        int cur_protection = backend.reg_read(ArmConst.UC_ARM_REG_R8).intValue();
        int tag = flags >> 24;
        boolean anywhere = (flags & MachO.VM_FLAGS_ANYWHERE) != 0;
        if (!anywhere) {
            throw new BackendException("_kernelrpc_mach_vm_map_trap fixed");
        }

        Pointer value = address.getPointer(0);
        UnidbgPointer pointer;
        if (mask != 0) {
            MachOLoader loader = (MachOLoader) emulator.getMemory();
            pointer = UnidbgPointer.pointer(emulator, loader.allocate(size, mask));
        } else {
            pointer = emulator.getMemory().mmap((int) size, cur_protection);
        }
        String msg = "_kernelrpc_mach_vm_map_trap target=" + target + ", address=" + address + ", value=" + value + ", size=0x" + Long.toHexString(size) + ", mask=0x" + Long.toHexString(mask) + ", flags=0x" + Long.toHexString(flags) + ", cur_protection=" + cur_protection + ", pointer=" + pointer + ", anywhere=true, tag=0x" + Integer.toHexString(tag);
        if (log.isDebugEnabled()) {
            log.debug(msg);
        } else {
            Logger log = LoggerFactory.getLogger("com.github.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
        }
        address.setPointer(0, pointer);
        return 0;
    }

    private int _kernelrpc_mach_vm_allocate_trap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int target = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer address = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        long r2 = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        long r3 = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        long size = r2 | (r3 << 32);
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
        int tag = flags >> 24;
        boolean anywhere = (flags & MachO.VM_FLAGS_ANYWHERE) != 0;
        if (!anywhere) {
            long start = address.getInt(0) & 0xffffffffL;
            long ret = emulator.getMemory().mmap2(start, (int) size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE, MAP_MY_FIXED, -1, 0);
            if (ret == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("_kernelrpc_mach_vm_allocate_trap fixed, address={}, size={}, flags=0x{}", address.getPointer(0), size, Integer.toHexString(flags));
                }
                if (tag != MachO.VM_MEMORY_REALLOC) {
                    throw new IllegalStateException("_kernelrpc_mach_vm_allocate_trap fixed, address=" + address.getPointer(0) + ", size=" + size + ", flags=0x" + Integer.toHexString(flags) + ", tag=" + tag);
                }
                return -1;
            }
            Pointer pointer = address.getPointer(0);
            pointer.write(0, new byte[(int) size], 0, (int) size);
            if (log.isDebugEnabled()) {
                log.debug("_kernelrpc_mach_vm_allocate_trap fixed, address={}, size={}, flags=0x{}, ret={}", pointer, size, Integer.toHexString(flags), ret);
            }
            return 0;
        }

        Pointer value = address.getPointer(0);
        UnidbgPointer pointer = emulator.getMemory().mmap((int) size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);
        pointer.write(0, new byte[(int) size], 0, (int) size);
        address.setPointer(0, pointer);
        String str = "_kernelrpc_mach_vm_allocate_trap target=" + target + ", address=" + address + ", value=" + value + ", size=0x" + Long.toHexString(size) + ", flags=0x" + Integer.toHexString(flags) + ", pointer=" + pointer + ", anywhere=true, tag=0x" + Integer.toHexString(tag);
        if (log.isDebugEnabled()) {
            log.debug(str);
        } else {
            Logger log = LoggerFactory.getLogger("com.github.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug(str);
            }
        }
        return 0;
    }

    private int _kernelrpc_mach_port_deallocate_trap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int task = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int name = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_deallocate_trap task={}, name={}", task, name);
        }
        return 0;
    }

    // https://github.com/lunixbochs/usercorn/blob/master/go/kernel/mach/ports.go
    private int mach_msg_trap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        Arm32RegisterContext context = emulator.getContext();
        UnidbgPointer msg = context.getR0Pointer();
        int option = context.getR1Int();
        int send_size = context.getR2Int();
        int rcv_size = context.getR3Int();
        int rcv_name = context.getR4Int();
        int timeout = context.getR5Int();
        int notify = context.getR6Int();

        msg.setSize(Math.max(send_size, rcv_size));

        final MachMsgHeader header = new MachMsgHeader(msg);
        header.unpack();
        if (log.isDebugEnabled()) {
            log.debug("mach_msg_trap msg={}, option=0x{}, send_size={}, rcv_size={}, rcv_name={}, timeout={}, notify={}, header={}", msg, Integer.toHexString(option), send_size, rcv_size, rcv_name, timeout, notify, header);
        }

        final Pointer request = msg.share(header.size());

        switch (header.msgh_id) {
            case 3409: // task_get_special_port
            {
                TaskGetSpecialPortRequest args = new TaskGetSpecialPortRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("task_get_special_port request={}", args);
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
                        log.debug("task_get_special_port reply={}", reply);
                    }

                    return MACH_MSG_SUCCESS;
                }
            }
            case 200: // host_info
            {
                HostInfoRequest args = new HostInfoRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("host_info args={}", args);
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
                        log.debug("host_info reply={}", reply);
                    }
                    return MACH_MSG_SUCCESS;
                }
            }
            case 3603: { // _thread_get_state
                ThreadStateRequest args = new ThreadStateRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("_thread_get_state args={}", request);
                }

                ThreadStateReply32 reply = new ThreadStateReply32(request);
                reply.unpack();
                header.setMsgBits(false);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                if (args.flavor != ThreadStateRequest.ARM_THREAD_STATE) {
                    reply.retCode = 4;
                    reply.pack();
                    if (log.isDebugEnabled()) {
                        log.debug("_thread_get_state reply={}, flavor={}", reply, args.flavor);
                    }
                    return MACH_MSG_SUCCESS;
                }

                reply.retCode = 0;
                reply.outCnt = ThreadStateRequest.ARM_THREAD_STATE_COUNT;
                for (int reg = ArmConst.UC_ARM_REG_R0; reg <= ArmConst.UC_ARM_REG_R12; reg++) {
                    reply.state.__r[reg - ArmConst.UC_ARM_REG_R0] = backend.reg_read(reg).intValue();
                }
                reply.state.__sp = backend.reg_read(ArmConst.UC_ARM_REG_SP).intValue();
                reply.state.__lr = backend.reg_read(ArmConst.UC_ARM_REG_LR).intValue();
                reply.state.__pc = backend.reg_read(ArmConst.UC_ARM_REG_PC).intValue();
                reply.state.__cpsr = backend.reg_read(ArmConst.UC_ARM_REG_CPSR).intValue();
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("_thread_get_state reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3612: { // _thread_info
                ThreadInfoRequest args = new ThreadInfoRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("_thread_info args={}", args);
                }

                final int THREAD_BASIC_INFO = 3;
                if (args.flavor != THREAD_BASIC_INFO) {
                    throw new UnsupportedOperationException();
                }

                ThreadBasicInfoReply reply = new ThreadBasicInfoReply(request);
                reply.unpack();

                header.setMsgBits(false);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                final int THREAD_BASIC_INFO_COUNT = 10;
                final int POLICY_TIMESHARE = 1;
                final int TH_STATE_RUNNING = 1;
                reply.retCode = 0;
                reply.outCnt = THREAD_BASIC_INFO_COUNT;
                reply.info.user_time.tv_sec = 0;
                reply.info.user_time.tv_usec = 177546;
                reply.info.system_time.tv_sec = 0;
                reply.info.system_time.tv_usec = 0;
                reply.info.cpu_usage = 343;
                reply.info.policy = POLICY_TIMESHARE;
                reply.info.run_state = TH_STATE_RUNNING;
                reply.info.flags = 0;
                reply.info.suspend_count = 0;
                reply.info.sleep_time = 0;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("_thread_info reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 1000: { // clock_get_time
                ClockGetTimeReply reply = new ClockGetTimeReply(request);
                reply.unpack();

                header.setMsgBits(false);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                long currentTimeMillis = System.currentTimeMillis();
                long nanoTime = System.nanoTime();
                long tv_sec = currentTimeMillis / 1000;
                long tv_usec = (currentTimeMillis % 1000) * 1000 + nanoTime % 1000;

                reply.retCode = 0;
                reply.tv_sec = (int) tv_sec;
                reply.tv_nsec = (int) tv_usec;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("clock_get_time reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 206: // host_get_clock_service
            {
                HostGetClockServiceRequest args = new HostGetClockServiceRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("host_get_clock_service args={}", args);
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
                    log.debug("host_get_clock_service reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3418: // semaphore_create
            {
                SemaphoreCreateRequest args = new SemaphoreCreateRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("semaphore_create args={}", args);
                }

                SemaphoreCreateReply reply = new SemaphoreCreateReply(request);
                reply.unpack();

                header.setMsgBits(true);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.semaphore.name = ThreadLocalRandom.current().nextInt() & 0x7fffffff;
                reply.semaphore.pad1 = 0;
                reply.semaphore.pad2 = 0;
                reply.semaphore.disposition = 17; // meaning?
                reply.semaphore.type = MACH_MSG_PORT_DESCRIPTOR;
                reply.pack();
                if (log.isDebugEnabled()) {
                    log.debug("semaphore_create reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3822: // vm_region_recurse_64
            {
                VmRegionRecurse32Request args = new VmRegionRecurse32Request(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_region_recurse_64 args={}", args);
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
                    log.debug("vm_region_recurse_64 header={}, memoryMap={}", header, memoryMap);
                }

                if (memoryMap == null) {
                    log.warn("vm_region_recurse_64 failed address=0x{}, size=0x{}", args.address, Integer.toHexString(args.size()));
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
                    log.debug("vm_region_recurse_64 reply={}, memoryMap={}", reply, memoryMap);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3413: { // task_set_exception_ports
                TaskSetExceptionPortsRequest args = new TaskSetExceptionPortsRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("task_set_exception_ports args={}, lr={}", args, UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }

                TaskSetExceptionPortsReply reply = new TaskSetExceptionPortsReply(request);
                reply.unpack();

                header.setMsgBits(false);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.NDR = args.NDR;
                reply.retCode = 0;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("task_set_exception_ports reply={}, header={}", reply, header);
                }

                return MACH_MSG_SUCCESS;
            }
            case 3414: // task_get_exception_ports
            {
                TaskGetExceptionPortsRequest args = new TaskGetExceptionPortsRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("task_get_exception_ports args={}, lr={}", args, UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
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
                    log.debug("task_get_exception_ports reply={}, header={}", reply, header);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3404: // mach_ports_lookup
            {
                MachPortsLookupReply32 reply = new MachPortsLookupReply32(request);
                reply.unpack();

                header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                header.msgh_size = 52;
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.retCode = 1;
                reply.outPort = (int) UnidbgPointer.nativeValue(request);
                reply.ret = 0;
                reply.mask = 0x2110000;
                reply.cnt = 0;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("mach_ports_lookup reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3808: // vm_copy
            {
                VmCopyRequest args = new VmCopyRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_copy args={}, lr={}", args, UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }

                byte[] data = backend.mem_read(args.source_address, args.size);
                emulator.getMemory().pointer(args.dest_address).write(data);

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
                    log.debug("vm_copy reply={}, header={}", reply, header);
                }
                return MACH_MSG_SUCCESS;
            }
            case 4813: // _kernelrpc_mach_vm_remap
            {
                VmRemapRequest args = new VmRemapRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("_kernelrpc_mach_vm_remap args={}, lr={}", args, UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }

                if ((args.anywhere != MachO.VM_FLAGS_OVERWRITE && args.anywhere != MachO.VM_FLAGS_FIXED) ||
                        args.mask != 0) {
                    throw new UnsupportedOperationException("_kernelrpc_mach_vm_remap anywhere=0x" + Integer.toHexString(args.anywhere) + ", mask=0x" + Long.toHexString(args.mask));
                }

                MachOLoader loader = (MachOLoader) emulator.getMemory();
                loader.remap(args);
                if (args.copy != 0) {
                    byte[] data = backend.mem_read(args.getSourceAddress(), args.size);
                    loader.pointer(args.target_address).write(data);
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
                    log.debug("_kernelrpc_mach_vm_remap reply={}, header={}", reply, header);
                }
                return MACH_MSG_SUCCESS;
            }
            case 404: { // vproc_mig_look_up2
                return vproc_mig_look_up2(request, header);
            }
            case 78945669: { // notify_server_register_plain
                NotifyServerRegisterPlainRequest args = new NotifyServerRegisterPlainRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    Pointer pointer = UnidbgPointer.pointer(emulator, args.name);
                    log.debug("notify_server_register_plain args={}, name={}", args, pointer == null ? null : new String(pointer.getByteArray(0, args.nameCnt), StandardCharsets.UTF_8));
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
                    log.debug("notify_server_register_plain reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 78945681: { // notify_server_get_state
                NotifyServerGetStateRequest args = new NotifyServerGetStateRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("notify_server_get_state args={}", args);
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
                    log.debug("notify_server_get_state reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 78945679: { // notify_server_cancel
                NotifyServerCancelRequest args = new NotifyServerCancelRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("notify_server_cancel args={}", args);
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
                    log.debug("notify_server_cancel reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 78945670: { // notify_server_register_check
                NotifyServerRegisterCheckRequest args = new NotifyServerRegisterCheckRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    Pointer pointer = UnidbgPointer.pointer(emulator, args.name & 0xffffffffL);
                    log.debug("notify_server_register_check args={}, name={}", args, pointer == null ? null : new String(pointer.getByteArray(0, args.namelen), StandardCharsets.UTF_8));
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
                    log.debug("notify_server_register_check reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 118: { // asl_server_message
                AslServerMessageRequest args = new AslServerMessageRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("asl_server_message args={}", args);
                }
                return MACH_MSG_SUCCESS;
            }
            case 78945673: { // notify_server_register_mach_port
                NotifyServerRegisterMachPortRequest args = new NotifyServerRegisterMachPortRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    Pointer pointer = UnidbgPointer.pointer(emulator, args.name);
                    log.debug("notify_server_register_mach_port args={}, name={}", args, pointer == null ? null : new String(pointer.getByteArray(0, args.namelen), StandardCharsets.UTF_8));
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
                    log.debug("notify_server_register_mach_port reply={}", reply);
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
                    log.debug("host_get_io_master reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 2873: { // io_service_get_matching_service
                IOServiceGetMatchingServiceRequest args = new IOServiceGetMatchingServiceRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("io_service_get_matching_service args={}, matching={}", args, args.getMatching());
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
                    log.debug("io_service_get_matching_service reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3218: { // _kernelrpc_mach_port_set_attributes
                MachPortSetAttributesRequest args = new MachPortSetAttributesRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("_kernelrpc_mach_port_set_attributes args={}", args);
                }

                MachPortSetAttributesReply reply = new MachPortSetAttributesReply(request);
                reply.unpack();

                header.setMsgBits(false);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.retCode = 0;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("_kernelrpc_mach_port_set_attributes reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3800: { // vm_region
                VmRegionRequest args = new VmRegionRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_region args={}", args);
                }

                if (args.flavor != VmRegionRequest.VM_REGION_BASIC_INFO) {
                    throw new UnsupportedOperationException("flavor=" + args.flavor);
                }

                VmRegionReply reply = new VmRegionReply(request);
                reply.unpack();

                header.setMsgBits(true);
                header.msgh_size = header.size() + reply.size() - 4;
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                MemoryMap memoryRegion = null;
                for (MemoryMap memoryMap : emulator.getMemory().getMemoryMap()) {
                    if (memoryMap.base >= args.address) {
                        memoryRegion = memoryMap;
                        break;
                    }
                }

                if (memoryRegion == null) {
                    header.setMsgBits(false);
                    header.msgh_size = 0x24;
                    header.pack();
                    reply.pad1 = 1;
                    reply.pack();

                    if (log.isDebugEnabled()) {
                        log.debug("vm_region reply={}", reply);
                    }
                    return MACH_MSG_SUCCESS;
                }

                reply.NDR.mig_vers = 1;
                reply.NDR.int_rep = 0;
                reply.retCode = 0x110000;
                reply.outCnt = VmRegionRequest.VM_REGION_BASIC_INFO_COUNT;
                reply.address = (int) memoryRegion.base;
                reply.size = (int) memoryRegion.size;
                reply.info.protection = memoryRegion.prot;
                reply.info.max_protection = memoryRegion.prot;
                reply.info.inheritance = 0;
                reply.info.shared = false;
                reply.info.reserved = false;
                reply.info.offset = 0;
                reply.info.behavior = 0;
                reply.info.user_wired_count = 0;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("vm_region reply={}, memoryRegion={}", reply, memoryRegion);
                }

                return MACH_MSG_SUCCESS;
            }
            case 3405: { // task_info
                TaskInfoRequest args = new TaskInfoRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("task_info args={}", args);
                }

                if (args.flavor == TaskInfoRequest.TASK_DYLD_INFO) {
                    TaskDyldInfoReply reply = new TaskDyldInfoReply(request);
                    reply.unpack();

                    header.setMsgBits(false);
                    header.msgh_size = header.size() + reply.size();
                    header.msgh_remote_port = header.msgh_local_port;
                    header.msgh_local_port = 0;
                    header.msgh_id += 100; // reply Id always equals reqId+100
                    header.pack();

                    reply.retCode = 0;
                    reply.task_info_outCnt = UnidbgStructure.calculateSize(TaskDyldInfo.class) / 4;
                    reply.dyldInfo.allocateAllImage(emulator);
                    reply.pack();

                    if (log.isDebugEnabled()) {
                        log.debug("task_info TASK_DYLD_INFO reply={}", reply);
                    }
                    return MACH_MSG_SUCCESS;
                }
                throw new UnsupportedOperationException("flavor=" + args.flavor);
            }
            case 217: // host_request_notification
                HostRequestNotificationRequest args = new HostRequestNotificationRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("host_request_notification args={}", args);
                }

                HostRequestNotificationReply reply = new HostRequestNotificationReply(request);
                reply.unpack();

                header.setMsgBits(false);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.retCode = 0;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("host_request_notification reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            case 216: // host_statistics
                if (host_statistics(request, header)) {
                    return MACH_MSG_SUCCESS;
                }
            default:
                log.warn("mach_msg_trap header={}, size={}, lr={}", header, header.size(), UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                if (log.isDebugEnabled() || LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
                    createBreaker(emulator).debug();
                }
                break;
        }

        return -1;
    }

    private static final int BOOTSTRAP_PORT = 11;
    private static final int CLOCK_SERVER_PORT = 13;

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

    private int sigprocmask(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int how = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer set = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oldset = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        return sigprocmask(emulator, how, set, oldset);
    }

    protected int gettimeofday(Emulator<?> emulator) {
        EditableArm32RegisterContext context = emulator.getContext();
        long currentTimeMillis = System.currentTimeMillis();
        long tv_sec = currentTimeMillis / 1000;
        long tv_usec = (currentTimeMillis % 1000) * 1000;
        context.setR1((int) tv_usec);
        if (log.isDebugEnabled()) {
            log.debug("gettimeofday tv_sec={}, tv_usec={}", tv_sec, tv_usec);
        }
        return (int) tv_sec;
    }

    private int writev(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer iov = context.getPointerArg(1);
        int iovcnt = context.getIntArg(2);
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

    private int rename(Emulator<?> emulator) {
        Arm32RegisterContext context = emulator.getContext();
        Pointer oldpath = context.getR0Pointer();
        Pointer newpath = context.getR1Pointer();
        String oldPath = oldpath.getString(0);
        String newPath = newpath.getString(0);
        int ret = emulator.getFileSystem().rename(oldPath, newPath);
        if (ret != 0) {
            log.info("rename oldPath={}, newPath={}", oldPath, newPath);
        } else {
            log.debug("rename oldPath={}, newPath={}", oldPath, newPath);
        }
        return 0;
    }

    private int mach_absolute_time(Emulator<?> emulator) {
        long nanoTime = System.nanoTime();
        if (log.isDebugEnabled()) {
            log.debug("mach_absolute_time nanoTime={}", nanoTime);
        }
        emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_R1, (int) (nanoTime >> 32));
        return (int) (nanoTime);
    }

    private int close_NOCANCEL(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        if (log.isDebugEnabled()) {
            log.debug("close_NOCANCEL fd={}", fd);
        }

        return close(emulator, fd);
    }

    private int read_NOCANCEL(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer buffer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        if (log.isDebugEnabled()) {
            log.debug("read_NOCANCEL fd={}, buffer={}, count={}", fd, buffer, count);
        }
        return read(emulator, fd, buffer, count);
    }

    private int shm_open(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pointer = context.getPointerArg(0);
        int oflags = context.getIntArg(1);
        int mode = context.getIntArg(2);
        String name = pointer.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("shm_open name={}, oflags=0x{}, mode={}", name, Integer.toHexString(oflags), Integer.toHexString(mode));
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int getppid(Emulator<?> emulator) {
        if (log.isDebugEnabled()) {
            log.debug("getppid");
        }
        return emulator.getPid();
    }

    private int getpid(Emulator<?> emulator) {
        int pid = emulator.getPid();
        log.debug("getpid pid={}", pid);
        return pid;
    }

    private int mkdir(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pathname = context.getPointerArg(0);
        int mode = context.getIntArg(1);
        String path = pathname.getString(0);
        if (emulator.getFileSystem().mkdir(path, mode)) {
            if (log.isDebugEnabled()) {
                log.debug("mkdir pathname={}, mode={}", path, mode);
            }
            return 0;
        } else {
            log.info("mkdir pathname={}, mode={}", path, mode);
            emulator.getMemory().setErrno(UnixEmulator.EACCES);
            return -1;
        }
    }

    private int rmdir(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pathname = context.getPointerArg(0);
        String path = pathname.getString(0);

        emulator.getFileSystem().rmdir(path);
        if (log.isDebugEnabled()) {
            log.debug("rmdir pathname={}", path);
        }
        return 0;
    }

    private int sendto(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int sockfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer buf = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int len = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        Pointer dest_addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        int addrlen = backend.reg_read(ArmConst.UC_ARM_REG_R5).intValue();

        return sendto(emulator, sockfd, buf, len, flags, dest_addr, addrlen);
    }

    private int connect(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int sockfd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int addrlen = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        return connect(emulator, sockfd, addr, addrlen);
    }

    private int sigaction(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int signum = context.getIntArg(0);
        Pointer act = context.getPointerArg(1);
        Pointer oldact = context.getPointerArg(2);

        return sigaction(emulator, signum, act, oldact);
    }

    private int fcntl(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int cmd = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int arg = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        return fcntl(emulator, fd, cmd, arg);
    }

    @Override
    protected int fcntl(Emulator<?> emulator, int fd, int cmd, long arg) {
        FileIO file = fdMap.get(fd);
        if (file != null && cmd == MachO.F_GETPATH) {
            Pointer pointer = UnidbgPointer.pointer(emulator, arg & 0xffffffffL);
            assert pointer != null;
            pointer.setString(0, file.getPath());
            return 0;
        }

        return super.fcntl(emulator, fd, cmd, arg);
    }

    private int mmap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        UnidbgPointer addr = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int length = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int prot = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        int flags = backend.reg_read(ArmConst.UC_ARM_REG_R3).intValue();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R4).intValue();
        int r5 = backend.reg_read(ArmConst.UC_ARM_REG_R5).intValue();
        long r6 = backend.reg_read(ArmConst.UC_ARM_REG_R6).intValue();
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
            Logger log = LoggerFactory.getLogger("com.github.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug(msg + ", base=0x" + Long.toHexString(base));
            }
        }
        return (int) base;
    }

    private int socket(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int domain = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        int type = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue() & 0x7ffff;
        int protocol = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        if (log.isDebugEnabled()) {
            log.debug("socket domain={}, type={}, protocol={}", domain, type, protocol);
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

    private int write(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
        Pointer buffer = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        byte[] data = buffer.getByteArray(0, count);
        if (log.isDebugEnabled()) {
            log.debug("write fd={}, buffer={}, count={}", fd, buffer, count);
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.write(data);
    }

    private int mprotect(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        long address = backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue() & 0xffffffffL;
        long length = backend.reg_read(ArmConst.UC_ARM_REG_R1).intValue();
        int prot = backend.reg_read(ArmConst.UC_ARM_REG_R2).intValue();
        long alignedAddress = address / ARMEmulator.PAGE_ALIGN * ARMEmulator.PAGE_ALIGN; // >> 12 << 12;
        long offset = address - alignedAddress;

        long alignedLength = ARM.alignSize(length + offset, emulator.getPageAlign());
        if (log.isDebugEnabled()) {
            log.debug("mprotect address=0x{}, alignedAddress=0x{}, offset={}, length={}, alignedLength={}, prot=0x{}", Long.toHexString(address), Long.toHexString(alignedAddress), offset, length, alignedLength, Integer.toHexString(prot));
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
