package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LongJumpException;
import com.github.unidbg.StopEmulatorException;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import com.github.unidbg.arm.context.EditableArm64RegisterContext;
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
import com.github.unidbg.ios.struct.kernel.DyldCacheHeader;
import com.github.unidbg.ios.struct.kernel.HostGetClockServiceReply;
import com.github.unidbg.ios.struct.kernel.HostGetClockServiceRequest;
import com.github.unidbg.ios.struct.kernel.HostInfoReply;
import com.github.unidbg.ios.struct.kernel.HostInfoRequest;
import com.github.unidbg.ios.struct.kernel.IOServiceAddNotificationRequest;
import com.github.unidbg.ios.struct.kernel.IOServiceGetMatchingServiceRequest;
import com.github.unidbg.ios.struct.kernel.MachMsgHeader;
import com.github.unidbg.ios.struct.kernel.MachPortOptions;
import com.github.unidbg.ios.struct.kernel.MachPortReply;
import com.github.unidbg.ios.struct.kernel.MachPortSetAttributesReply;
import com.github.unidbg.ios.struct.kernel.MachPortSetAttributesRequest;
import com.github.unidbg.ios.struct.kernel.MachPortTypeReply;
import com.github.unidbg.ios.struct.kernel.MachPortTypeRequest;
import com.github.unidbg.ios.struct.kernel.MachPortsLookupReply64;
import com.github.unidbg.ios.struct.kernel.MachTimebaseInfo;
import com.github.unidbg.ios.struct.kernel.MachVmMapReply;
import com.github.unidbg.ios.struct.kernel.MachVmMapRequest;
import com.github.unidbg.ios.struct.kernel.MakeMemoryEntryReply;
import com.github.unidbg.ios.struct.kernel.MakeMemoryEntryRequest;
import com.github.unidbg.ios.struct.kernel.NotifyServerCancelReply;
import com.github.unidbg.ios.struct.kernel.NotifyServerCancelRequest;
import com.github.unidbg.ios.struct.kernel.NotifyServerGetStateReply;
import com.github.unidbg.ios.struct.kernel.NotifyServerGetStateRequest;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterCheck64Request;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterCheckReply;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterMachPort64Request;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterMachPortReply;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterPlain64Request;
import com.github.unidbg.ios.struct.kernel.NotifyServerRegisterPlainReply;
import com.github.unidbg.ios.struct.kernel.ProcBsdShortInfo;
import com.github.unidbg.ios.struct.kernel.Pthread;
import com.github.unidbg.ios.struct.kernel.Pthread64;
import com.github.unidbg.ios.struct.kernel.PurgableControlReply;
import com.github.unidbg.ios.struct.kernel.PurgableControlRequest;
import com.github.unidbg.ios.struct.kernel.RLimit;
import com.github.unidbg.ios.struct.kernel.RUsage64;
import com.github.unidbg.ios.struct.kernel.SemaphoreCreateReply;
import com.github.unidbg.ios.struct.kernel.SemaphoreCreateRequest;
import com.github.unidbg.ios.struct.kernel.Stat64;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.ios.struct.kernel.TaskBasicInfoReply64V2;
import com.github.unidbg.ios.struct.kernel.TaskDyldInfoReply;
import com.github.unidbg.ios.struct.kernel.TaskGetExceptionPortsReply;
import com.github.unidbg.ios.struct.kernel.TaskGetExceptionPortsRequest;
import com.github.unidbg.ios.struct.kernel.TaskGetSpecialPortReply;
import com.github.unidbg.ios.struct.kernel.TaskGetSpecialPortRequest;
import com.github.unidbg.ios.struct.kernel.TaskInfoRequest;
import com.github.unidbg.ios.struct.kernel.TaskSetExceptionPortsReply;
import com.github.unidbg.ios.struct.kernel.TaskSetExceptionPortsRequest;
import com.github.unidbg.ios.struct.kernel.TaskThreadsReply64;
import com.github.unidbg.ios.struct.kernel.TaskVmInfoReply64;
import com.github.unidbg.ios.struct.kernel.ThreadBasicInfoReply;
import com.github.unidbg.ios.struct.kernel.ThreadInfoRequest;
import com.github.unidbg.ios.struct.kernel.ThreadStateReply64;
import com.github.unidbg.ios.struct.kernel.ThreadStateRequest;
import com.github.unidbg.ios.struct.kernel.VmCopy64Request;
import com.github.unidbg.ios.struct.kernel.VmCopyReply;
import com.github.unidbg.ios.struct.kernel.VmReadOverwriteReply;
import com.github.unidbg.ios.struct.kernel.VmReadOverwriteRequest;
import com.github.unidbg.ios.struct.kernel.VmRegion64Reply;
import com.github.unidbg.ios.struct.kernel.VmRegion64Request;
import com.github.unidbg.ios.struct.kernel.VmRegionRecurse64Reply;
import com.github.unidbg.ios.struct.kernel.VmRegionRecurse64Request;
import com.github.unidbg.ios.struct.kernel.VmRemapReply;
import com.github.unidbg.ios.struct.kernel.VmRemapRequest;
import com.github.unidbg.ios.struct.sysctl.IfMsgHeader;
import com.github.unidbg.ios.struct.sysctl.KInfoProc64;
import com.github.unidbg.ios.struct.sysctl.SockAddrDL;
import com.github.unidbg.ios.struct.sysctl.TaskDyldInfo;
import com.github.unidbg.ios.struct.sysctl.TaskVmInfo64;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.thread.PopContextException;
import com.github.unidbg.thread.RunnableTask;
import com.github.unidbg.thread.ThreadContextSwitchException;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.struct.TimeSpec;
import com.github.unidbg.unix.struct.TimeVal64;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

import static com.github.unidbg.file.ios.DarwinFileIO.XATTR_CREATE;
import static com.github.unidbg.file.ios.DarwinFileIO.XATTR_REPLACE;
import static com.github.unidbg.ios.MachO.MAP_MY_FIXED;
import static com.github.unidbg.ios.file.SocketIO.AF_LINK;
import static com.github.unidbg.ios.file.SocketIO.AF_ROUTE;

public class ARM64SyscallHandler extends DarwinSyscallHandler {

    private static final Logger log = LoggerFactory.getLogger(ARM64SyscallHandler.class);

    private final SvcMemory svcMemory;

    protected ARM64SyscallHandler(SvcMemory svcMemory) {
        super();

        this.svcMemory = svcMemory;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void hook(Backend backend, int intno, int swi, Object user) {
        Emulator<DarwinFileIO> emulator = (Emulator<DarwinFileIO>) user;
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

        int NR = backend.reg_read(Arm64Const.UC_ARM64_REG_X16).intValue();
        String syscall = null;
        Throwable exception = null;
        try {
            if (swi == 0 && NR == Svc.POST_CALLBACK_SYSCALL_NUMBER && backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue() == 0) { // postCallback
                int number = backend.reg_read(Arm64Const.UC_ARM64_REG_X12).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handlePostCallback(emulator);
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi);
            }
            if (swi == 0 && NR == Svc.PRE_CALLBACK_SYSCALL_NUMBER && backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue() == 0) { // preCallback
                int number = backend.reg_read(Arm64Const.UC_ARM64_REG_X12).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handlePreCallback(emulator);
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi);
            }
            if (swi != DARWIN_SWI_SYSCALL) {
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
                throw new BackendException("svc number: " + swi + ", NR=" + NR + ", intno=" + intno);
            }

            if (log.isTraceEnabled()) {
                log.debug("handle syscall NR={}", NR);
                ARM.showRegs64(emulator, null);
            }
            Cpsr.getArm64(backend).setCarry(false);

            boolean isIndirect = NR == 0;
            if (isIndirect) {
                int indirectNR = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
                if (!handleIndirect(emulator, indirectNR)) {
                    log.warn("handleInterrupt intno={}, indirectNR={}, svcNumber=0x{}, PC={}", intno, indirectNR, Integer.toHexString(swi), pc);
                    if (log.isDebugEnabled() || LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
                        createBreaker(emulator).debug();
                    }
                }
                return;
            }

            if (handleSyscall(emulator, NR)) {
                return;
            }

            switch (NR) {
                case -3:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mach_absolute_time());
                    return;
                case -10:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_vm_allocate_trap(emulator));
                    return;
                case -12:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_vm_deallocate_trap(emulator));
                    return;
                case -14:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_vm_protect_trap(emulator));
                    return;
                case -15:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_vm_map_trap(emulator));
                    return;
                case -16:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_port_allocate_trap(emulator));
                    return;
                case -18:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_port_deallocate_trap(emulator));
                    return;
                case -19:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_port_mod_refs_trap(emulator));
                    return;
                case -21:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_port_insert_right_trap(emulator));
                    return;
                case -22: // _mach_port_insert_member
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _mach_port_insert_member(emulator));
                    return;
                case -24:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_port_construct_trap(emulator));
                    return;
                case -26: // mach_port_t mach_reply_port(...)
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mach_reply_port());
                    return;
                case -27:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, thread_self_trap());
                    return;
                case -28: // mach_port_name_t task_self_trap(void)
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, task_self_trap());
                    return;
                case -29:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, host_self_trap());
                    return;
                case -31:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mach_msg_trap(emulator));
                    return;
                case -33: // _semaphore_signal_trap
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _os_semaphore_signal(emulator));
                    return;
                case -36: // _semaphore_wait_trap
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _semaphore_wait_trap(emulator));
                    return;
                case -38: // semaphore_timedwait_trap
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, semaphore_timedwait_trap(emulator));
                    return;
                case -41: // _xpc_mach_port_guard
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _kernelrpc_mach_port_guard_trap(emulator));
                    return;
                case -47:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, kern_invalid());
                    return;
                case -59: // swtch_pri
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, swtch_pri(emulator));
                    return;
                case -61:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, thread_switch(emulator));
                    return;
                case -89:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _mach_timebase_info(emulator));
                    return;
                case -91: // mk_timer_create
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _mk_timer_create());
                    return;
                case -93: // mk_timer_arm
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _mk_timer_arm(emulator));
                    return;
                case -94: // mk_timer_cancel
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _mk_timer_cancel(emulator));
                    return;
                case 1:
                    exit(emulator);
                    return;
                case 2:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fork(emulator));
                    return;
                case 4:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, write(emulator, 0));
                    return;
                case 6:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, closeWithOffset(emulator, 0));
                    return;
                case 10:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, unlink(emulator));
                    return;
                case 15:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, chmod(emulator));
                    return;
                case 16:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, chown(emulator));
                    return;
                case 20:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getpid(emulator));
                    return;
                case 24: // getuid
                case 25: // geteuid
                case 43: // getegid
                case 47: // getgid
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
                    return;
                case 33:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, access(emulator));
                    return;
                case 34:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, chflags(emulator));
                    return;
                case 35:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fchflags(emulator));
                    return;
                case 37:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, kill(emulator));
                    return;
                case 39:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getppid(emulator));
                    return;
                case 42:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pipe(emulator));
                    return;
                case 46:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sigaction(emulator));
                    return;
                case 48:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sigprocmask(emulator));
                    return;
                case 52:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sigpending(emulator));
                    return;
                case 53:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sigaltstack(emulator));
                    return;
                case 54:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ioctl(emulator));
                    return;
                case 58:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, readlink(emulator));
                    return;
                case 65:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, msync(emulator));
                    return;
                case 73:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, munmap(emulator));
                    return;
                case 74:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mprotect(emulator));
                    return;
                case 75:
                    syscall = "posix_madvise";
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
                    return;
                case 89:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getdtablesize());
                    return;
                case 90:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, dup2(emulator));
                    return;
                case 92:
                case 406: // fcntl_NOCANCEL
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fcntl(emulator));
                    return;
                case 93:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, newselect(emulator));
                    return;
                case 95:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fsync(emulator));
                    return;
                case 97:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, socket(emulator, 0));
                    return;
                case 98:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, connect(emulator, 0));
                    return;
                case 116:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, gettimeofday(emulator));
                    return;
                case 117:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getrusage(emulator));
                    return;
                case 121:
                case 412: // __writev_nocancel
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, writev(emulator));
                    return;
                case 123:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fchown(emulator));
                    return;
                case 124:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fchmod(emulator));
                    return;
                case 128:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, rename(emulator));
                    return;
                case 131:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, flock(emulator));
                    return;
                case 133:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sendto(emulator));
                    return;
                case 136:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mkdir(emulator));
                    return;
                case 137:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, rmdir(emulator));
                    return;
                case 138:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, utimes(emulator, 0));
                    return;
                case 139:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, futimes(emulator));
                    return;
                case 159:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, unmount(emulator));
                    return;
                case 169:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, csops(emulator));
                    return;
                case 194:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getrlimit(emulator));
                    return;
                case 195:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, setrlimit(emulator));
                    return;
                case 197:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mmap(emulator));
                    return;
                case 199:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, lseek(emulator));
                    return;
                case 201:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ftruncate(emulator));
                    return;
                case 202:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sysctl(emulator, 0));
                    return;
                case 216:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, open_dprotected_np(emulator));
                    return;
                case 220:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getattrlist(emulator));
                    return;
                case 221:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, setattrlist(emulator));
                    return;
                case 234:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getxattr(emulator));
                    return;
                case 236:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, setxattr(emulator));
                    return;
                case 237:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fsetxattr(emulator));
                    return;
                case 238:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, removexattr(emulator));
                    return;
                case 240:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, listxattr(emulator));
                    return;
                case 241:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, flistxattr(emulator));
                    return;
                case 266:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, shm_open(emulator));
                    return;
                case 282:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, chmodx_np(emulator));
                    return;
                case 283:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fchmodx_np(emulator));
                    return;
                case 286:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pthread_getugid_np(emulator));
                    return;
                case 294:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, shared_region_check_np(emulator));
                    return;
                case 301:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, psynch_mutexwait(emulator));
                    return;
                case 302:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, psynch_mutexdrop(emulator));
                    return;
                case 303:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, psynch_cvbroad(emulator));
                    return;
                case 305:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, psynch_cvwait(emulator));
                    return;
                case 307:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, psynch_rw_wrlock(emulator));
                    return;
                case 308:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, psynch_rw_unlock(emulator));
                    return;
                case 327:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, issetugid());
                    return;
                case 328:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pthread_kill(emulator));
                    return;
                case 329:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pthread_sigmask(emulator));
                    return;
                case 330:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sigwait(emulator));
                    return;
                case 331:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, disable_threadsignal(emulator));
                    return;
                case 334:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, semwait_signal(emulator));
                    return;
                case 336:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, proc_info(emulator, 0));
                    return;
                case 338:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, stat64(emulator, 0));
                    return;
                case 339:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fstat(emulator));
                    return;
                case 340:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, lstat(emulator, 0));
                    return;
                case 341:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, statx_np(emulator));
                    return;
                case 342:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, lstatx_np(emulator));
                    return;
                case 343:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fstatx_np(emulator));
                    return;
                case 344:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getdirentries64(emulator, 0));
                    return;
                case 345:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, statfs64(emulator));
                    return;
                case 346:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fstatfs64(emulator));
                    return;
                case 347:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getfsstat64(emulator, 0));
                    return;
                case 357:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getaudit_addr(emulator));
                    return;
                case 360:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, bsdthread_create(emulator));
                    return;
                case 361:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, bsdthread_terminate(emulator));
                    return;
                case 366:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, bsdthread_register(emulator));
                    return;
                case 367:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _workq_open(emulator));
                    return;
                case 368:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, _workq_kernreturn(emulator));
                    return;
                case 369:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, kevent64(emulator));
                    return;
                case 372:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, thread_selfid(emulator));
                    return;
                case 381:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sandbox_ms(emulator));
                    return;
                case 3:
                case 396:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, read_NOCANCEL(emulator, 0));
                    return;
                case 397:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, write_NOCANCEL(emulator));
                    return;
                case 5:
                case 398:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, open_NOCANCEL(emulator, 0));
                    return;
                case 399:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, close_NOCANCEL(emulator));
                    return;
                case 423:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, semwait_signal(emulator));
                    return;
                case 428:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, audit_session_self());
                    return;
                case 443:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, guarded_kqueue_np(emulator));
                    return;
                case 0x80000000:
                    NR = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
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

    private long newselect(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int nfds = context.getIntArg(0);
        Pointer readfds = context.getPointerArg(1);
        Pointer writefds = context.getPointerArg(2);
        Pointer exceptfds = context.getPointerArg(3);
        Pointer timeout = context.getPointerArg(4);
        int size = (nfds - 1) / 8 + 1;
        if (log.isDebugEnabled()) {
            log.debug("newselect nfds={}, readfds={}, writefds={}, exceptfds={}, timeout={}", nfds, readfds, writefds, exceptfds, timeout);
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
        throw new AbstractMethodError("newselect nfds=" + nfds + ", readfds=null, writefds=" + writefds + ", exceptfds=null, timeout=" + timeout);
    }

    private long fstatx_np(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer sb = context.getPointerArg(1);
        Pointer fsacl = context.getPointerArg(2);
        Pointer fsacl_size = context.getPointerArg(3);
        DarwinFileIO io = fdMap.get(fd);
        if (io != null) {
            fsacl_size.setLong(0, 0);
            io.fstat(emulator, new Stat64(sb));
            log.debug("fstatx_np fd={}, sb={}, fsacl={}, fsacl_size={}, io={}", fd, sb, fsacl, fsacl_size, io);
            return 0;
        }

        int errno = UnixEmulator.ENOENT;
        if (verbose) {
            System.out.printf("File fstatx_np '%s' errno is %d from %s%n", fd, errno, emulator.getContext().getLRPointer());
        }
        Cpsr.getArm64(emulator.getBackend()).setCarry(true);
        return errno;
    }

    private long lstatx_np(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer obj = context.getPointerArg(0);
        Pointer sb = context.getPointerArg(1);
        Pointer fsacl = context.getPointerArg(2);
        Pointer fsacl_size = context.getPointerArg(3);
        String path = obj.getString(0);
        FileResult<DarwinFileIO> result = resolve(emulator, path, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            fsacl_size.setLong(0, 0);
            result.io.fstat(emulator, new Stat64(sb));
            log.debug("lstatx_np path={}, sb={}, fsacl={}, fsacl_size={}, result={}", path, sb, fsacl, fsacl_size, result.io);
            return 0;
        }

        int errno = result != null ? result.errno : UnixEmulator.ENOENT;
        if (verbose) {
            System.out.printf("File lstatx_np '%s' errno is %d from %s%n", path, errno, emulator.getContext().getLRPointer());
        }
        Cpsr.getArm64(emulator.getBackend()).setCarry(true);
        return errno;
    }

    private long statx_np(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer obj = context.getPointerArg(0);
        Pointer sb = context.getPointerArg(1);
        Pointer fsacl = context.getPointerArg(2);
        Pointer fsacl_size = context.getPointerArg(3);
        String path = obj.getString(0);
        FileResult<DarwinFileIO> result = resolve(emulator, path, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            fsacl_size.setLong(0, 0);
            result.io.fstat(emulator, new Stat64(sb));
            log.debug("statx_np path={}, sb={}, fsacl={}, fsacl_size={}, result={}", path, sb, fsacl, fsacl_size, result.io);
            return 0;
        }

        int errno = result != null ? result.errno : UnixEmulator.ENOENT;
        if (verbose) {
            System.out.printf("File statx '%s' errno is %d from %s%n", path, errno, emulator.getContext().getLRPointer());
        }
        Cpsr.getArm64(emulator.getBackend()).setCarry(true);
        return errno;
    }

    private long kern_invalid() {
        return 0x4; // KERN_INVALID_ARGUMENT
    }

    private long getrusage(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int who = context.getIntArg(0);
        Pointer r_usage = context.getPointerArg(1);
        RUsage64 usage64 = new RUsage64(r_usage);
        usage64.unpack();
        if (log.isDebugEnabled()) {
            log.debug("getrusage who={}, r_usage={}, usage64={}", who, r_usage, usage64);
        }
        usage64.fillDefault();
        usage64.pack();
        return 0;
    }

    private int unmount(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer target = context.getPointerArg(0);
        int flags = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("unmount target={}, flags=0x{}", target.getString(0), Integer.toHexString(flags));
        }
        return 0;
    }

    private UnidbgPointer shared_region;

    private int shared_region_check_np(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer start_address = context.getPointerArg(0);
        if (shared_region == null) {
            shared_region = emulator.getMemory().mmap(emulator.getPageAlign(), UnicornConst.UC_PROT_READ);
            DyldCacheHeader dyldCacheHeader = new DyldCacheHeader(shared_region);
            dyldCacheHeader.pack();
        }
        if (log.isDebugEnabled()) {
            log.debug("shared_region_check_np start_address={}, LR={}", start_address, context.getLRPointer());
        }
        start_address.setPointer(0, shared_region);
        return 0;
    }

    private int getdtablesize() {
        return 0x1000;
    }

    // see https://fergofrog.com/code/cbowser/xnu/BUILD/obj/EXPORT_HDRS/osfmk/kern/cs_blobs.h.html#_M/CS_VALID
    private static final int CS_OPS_STATUS = 0; /* return status */
    private static final int CS_GET_TASK_ALLOW = 0x00000004; /* has get-task-allow entitlement */
    private static final int CS_INSTALLER = 0x00000008; /* has installer entitlement */
    private static final int CS_HARD = 0x0000100; /* don't load invalid pages */
    private static final int CS_RESTRICT = 0x0000800; /* tell dyld to treat restricted */
    private static final int CS_ENFORCEMENT = 0x0001000; /* require enforcement */
    private static final int CS_REQUIRE_LV = 0x0002000; /* require library validation */
    private static final int CS_ENTITLEMENTS_VALIDATED = 0x0004000; /* code signature permits restricted entitlements */
    private static final int CS_DYLD_PLATFORM = 0x2000000; /* dyld used to load this is a platform binary */
    private static final int CS_PLATFORM_BINARY = 0x4000000; /* this is a platform binary */
    private static final int CS_DEBUGGED = 0x10000000; /* process is currently or has previously been debugged and allowed to run with invalid pages */
    private static final int CS_SIGNED = 0x20000000; /* process has a signature (may have gone invalid) */

    private static final int CS_OPS_CDHASH = 5; /* get code directory hash */

    private long csops(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        int op = context.getIntArg(1);
        Pointer addr = context.getPointerArg(2);
        int length = context.getIntArg(3);
        if (log.isDebugEnabled()) {
            log.debug("csops pid={}, op={}, addr={}, length={}", pid, op, addr, length);
        }
        if (op == CS_OPS_STATUS) {
            addr.setInt(0, CS_HARD | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV | CS_ENTITLEMENTS_VALIDATED | CS_DYLD_PLATFORM | CS_PLATFORM_BINARY | CS_SIGNED);
            return 0;
        } else if (op == CS_OPS_CDHASH) {
            byte[] cdhash = new byte[length];
            for (int i = 0; i < length; i++) {
                cdhash[i] = (byte) (i + 0x10);
            }
            addr.write(0, cdhash, 0, length);
            return 0;
        } else {
            log.info("csops pid={}, op={}, addr={}, length={}", pid, op, addr, length);
            Logger log = LoggerFactory.getLogger(AbstractEmulator.class);
            if (log.isDebugEnabled()) {
                emulator.attach().debug();
            }
            return -1;
        }
    }

    private long msync(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer addr = context.getPointerArg(0);
        int len = context.getIntArg(1);
        int flags = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("msync addr={}, len={}, flags=0x{}", addr, len, Integer.toHexString(flags));
        }
        return 0;
    }

    private long fchown(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int uid = context.getIntArg(1);
        int gid = context.getIntArg(2);
        DarwinFileIO io = fdMap.get(fd);
        if (io != null) {
            int ret = io.chown(uid, gid);
            if (ret == -1) {
                log.info("fchown fd={}, uid={}, gid={}", fd, uid, gid);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("fchown fd={}, uid={}, gid={}", fd, uid, gid);
                }
            }
            return ret;
        } else {
            log.info("fchown fd={}, uid={}, gid={}", fd, uid, gid);
            Cpsr.getArm64(emulator.getBackend()).setCarry(true);
            return UnixEmulator.ENOENT;
        }
    }

    private long chown(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        int uid = context.getIntArg(1);
        int gid = context.getIntArg(2);
        String pathname = path.getString(0);
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            int ret = result.io.chown(uid, gid);
            if (ret == -1) {
                log.info("chown path={}, uid={}, gid={}", pathname, uid, gid);
            } else {
                log.debug("chown path={}, uid={}, gid={}", pathname, uid, gid);
            }
            return ret;
        } else {
            log.info("chown path={}, uid={}, gid={}, result={}", pathname, uid, gid, result);
            Cpsr.getArm64(emulator.getBackend()).setCarry(true);
            return UnixEmulator.ENOENT;
        }
    }

    private boolean handleMachineDependentSyscall(Emulator<?> emulator, int NR) {
        Backend backend = emulator.getBackend();
        switch (NR) {
            case 0:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sys_icache_invalidate(emulator));
                return true;
            case 1:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sys_dcache_flush(emulator));
                return true;
            case 2:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pthread_set_self(emulator));
                return true;
        }
        return false;
    }

    private long sys_dcache_flush(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer address = context.getPointerArg(0);
        long size = context.getLongArg(1);
        if (log.isDebugEnabled()) {
            log.debug("sys_dcache_flush address={}, size={}", address, size);
        }
        return 0;
    }

    private long sys_icache_invalidate(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer address = context.getPointerArg(0);
        long size = context.getLongArg(1);
        if (log.isDebugEnabled()) {
            log.debug("sys_icache_invalidate address={}, size={}", address, size);
        }
        return 0;
    }

    private long _mach_port_insert_member(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int task = context.getIntArg(0);
        int name = context.getIntArg(1);
        int pset = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("_mach_port_insert_member task={}, name={}, pset={}", task, name, pset);
        }
        if (verbose) {
            System.out.printf("mach_port_insert_member %d with pset=0x%x from %s%n", name, pset, emulator.getContext().getLRPointer());
        }
        return 0;
    }

    private long _mk_timer_create() {
        if (log.isDebugEnabled()) {
            log.debug("_mk_timer_create");
        }
        return STATIC_PORT;
    }

    private long _mk_timer_arm(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int port = context.getIntArg(0);
        long time = context.getLongArg(1);
        if (log.isDebugEnabled()) {
            log.debug("_mk_timer_arm port={}, time={}", port, time);
        }
        return 0;
    }

    private long _mk_timer_cancel(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int name = context.getIntArg(0);
        Pointer result_time = context.getPointerArg(1);
        if (log.isDebugEnabled()) {
            log.debug("_mk_timer_cancel name={}, result_time={}", name, result_time);
        }
        return 0;
    }

    private long mkdir(Emulator<?> emulator) {
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
        Pointer path = context.getPointerArg(0);
        String pathname = path.getString(0);

        emulator.getFileSystem().rmdir(pathname);
        if (log.isDebugEnabled()) {
            log.debug("rmdir pathname={}", path);
        }
        return 0;
    }

    /**
     * set file access and modification times
     * int utimes(const char *path, const struct timeval times[2]);
     */
    private long utimes(Emulator<?> emulator, int offset) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(offset);
        Pointer times = context.getPointerArg(offset + 1);
        String pathname = path.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("utimes pathname={}, times={}", pathname, times);
        }
        return 0;
    }

    private long futimes(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer times = context.getPointerArg(1);
        if (log.isDebugEnabled()) {
            log.debug("futimes fd={}, times={}", fd, times);
        }
        return 0;
    }

    protected boolean handleIndirect(Emulator<DarwinFileIO> emulator, int indirectNR) {
        Backend backend = emulator.getBackend();
        switch (indirectNR) {
            case 3:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, read_NOCANCEL(emulator, 1));
                return true;
            case 4:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, write(emulator, 1));
                return true;
            case 5:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, open_NOCANCEL(emulator, 1));
                return true;
            case 6:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, closeWithOffset(emulator, 1));
                return true;
            case 20:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getpid(emulator));
                return true;
            case 39:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getppid(emulator));
                return true;
            case 97:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, socket(emulator, 1));
                return true;
            case 98:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, connect(emulator, 1));
                return true;
            case 138:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, utimes(emulator, 1));
                return true;
            case 190:
            case 340:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, lstat(emulator, 1));
                return true;
            case 202:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sysctl(emulator, 1));
                return true;
            case 336:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, proc_info(emulator, 1));
                return true;
            case 338:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, stat64(emulator, 1));
                return true;
            case 344:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getdirentries64(emulator, 1));
                return true;
            case 347:
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getfsstat64(emulator, 1));
                return true;
        }
        return false;
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

    private long semaphore_timedwait_trap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int port = context.getIntArg(0);
        log.info("semaphore_timedwait_trap port={}", port);
        Logger log = ARM64SyscallHandler.log;
        if (!log.isDebugEnabled()) {
            log = LoggerFactory.getLogger(AbstractEmulator.class);
        }
        if (log.isDebugEnabled()) {
            createBreaker(emulator).debug();
        }
        return 0;
    }

    private long _os_semaphore_signal(Emulator<?> emulator) {
        int semaphore = emulator.getContext().getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("_os_semaphore_signal semaphore={}", semaphore);
        }
        if (semaphore != 0) {
            semaphoreMap.put(semaphore, Boolean.TRUE);
        }
        Logger log = ARM64SyscallHandler.log;
        if (!log.isDebugEnabled()) {
            log = LoggerFactory.getLogger(AbstractEmulator.class);
        }
        if (log.isDebugEnabled()) {
            createBreaker(emulator).debug();
        }
        return 0;
    }

    private int _kernelrpc_mach_port_allocate_trap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int task = context.getIntArg(0);
        int right = context.getIntArg(1);
        Pointer name = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_allocate_trap task={}, right={}, name={}", task, right, name);
        }
        name.setInt(0, STATIC_PORT);
        if (verbose) {
            System.out.printf("mach_port_allocate %d with right=0x%x from %s%n", STATIC_PORT, right, emulator.getContext().getLRPointer());
        }
        return 0;
    }

    private int pthread_set_self(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer self = context.getPointerArg(0);
        Pthread pthread = new Pthread64(self.getPointer(0));
        pthread.unpack();
        UnidbgPointer tsd = pthread.getTSD();
        emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_TPIDRRO_EL0, tsd.peer);
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setErrnoPointer(pthread.getErrno());

        if (log.isDebugEnabled()) {
            String threadName = pthread.getName();
            log.debug("pthread_set_self={}, pthread={}, threadName={}, LR={}", self, pthread, threadName, emulator.getContext().getLRPointer());
        }
        return 0;
    }

    private int thread_switch(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int thread_name = context.getIntArg(0);
        int option = context.getIntArg(1);
        int option_time = context.getIntArg(2);
        log.info("thread_switch thread_name={}, option={}, option_time={}", thread_name, option, option_time);
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

    private long psynch_rw_unlock(Emulator<?> emulator) {
        // TODO: implement
        log.info("psynch_rw_unlock LR={}", emulator.getContext().getLRPointer());
        return 0;
    }

    private long psynch_rw_wrlock(Emulator<?> emulator) {
        // TODO: implement
        log.info("psynch_rw_wrlock LR={}", emulator.getContext().getLRPointer());
        return 0;
    }

    /**
     * psynch_mutexwait: This system call is used for contended psynch mutexes to block.
     */
    private int psynch_mutexwait(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer mutex = context.getPointerArg(0);
        int mgen = context.getIntArg(1);
        int ugen = context.getIntArg(2);
        long tid = context.getLongArg(3);
        int flags = context.getIntArg(4);
        if (log.isDebugEnabled()) {
            log.debug("psynch_mutexwait mutex={}, mgen={}, ugen={}, tid={}, flags=0x{}, LR={}", mutex, mgen, ugen, tid, Integer.toHexString(flags), context.getLRPointer());
        }
        return 0;
    }

    private int psynch_mutexdrop(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer mutex = context.getPointerArg(0);
        int mgen = context.getIntArg(1);
        int ugen = context.getIntArg(2);
        long tid = context.getLongArg(3);
        int flags = context.getIntArg(4);
        if (log.isDebugEnabled()) {
            log.debug("psynch_mutexdrop mutex={}, mgen={}, ugen={}, tid={}, flags=0x{}, LR={}", mutex, mgen, ugen, tid, Integer.toHexString(flags), context.getLRPointer());
        }
        return 0;
    }

    private int psynch_cvwait(Emulator<?> emulator) {
        Logger log = LoggerFactory.getLogger(AbstractEmulator.class);
        if (threadDispatcherEnabled) {
            if (log.isTraceEnabled()) {
                emulator.attach().debug();
            }
            throw new ThreadContextSwitchException();
        }

        log.info("psynch_cvwait LR=" + emulator.getContext().getLRPointer());
        if (log.isDebugEnabled()) {
            emulator.attach().debug();
        }
        emulator.getMemory().setErrno(UnixEmulator.EINTR);
        return -1;
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

    private int pthread_getugid_np(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer uid = context.getPointerArg(0);
        Pointer gid = context.getPointerArg(1);
        if (log.isDebugEnabled()) {
            log.debug("pthread_getugid_np uid={}, gid={}", uid, gid);
        }
        uid.setInt(0, 0);
        gid.setInt(0, 0);
        return 0;
    }

    private int closeWithOffset(Emulator<?> emulator, int offset) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(offset);
        if (log.isDebugEnabled()) {
            log.debug("close fd={}, LR={}", fd, context.getLRPointer());
        }

        return close(emulator, fd);
    }

    private int lseek(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        long offset = context.getLongArg(1);
        int whence = context.getIntArg(2);
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

    private long ftruncate(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int length = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("ftruncate fd={}, length={}, LR={}", fd, length, context.getLRPointer());
        }
        FileIO file = fdMap.get(fd);
        if (file == null) {
            throw new UnsupportedOperationException("fd=" + fd + ", map=" + fdMap);
        }
        return file.ftruncate(length);
    }

    private int unlink(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pathname = context.getPointerArg(0);
        String path = FilenameUtils.normalize(pathname.getString(0), true);
        emulator.getFileSystem().unlink(path);
        return 0;
    }

    private int getdirentries64(Emulator<?> emulator, int index) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(index);
        UnidbgPointer buf = context.getPointerArg(index + 1);
        int bufSize = context.getIntArg(index + 2);
        Pointer basep = context.getPointerArg(index + 3);

        DarwinFileIO io = fdMap.get(fd);
        if (log.isDebugEnabled()) {
            log.debug("getdirentries64 fd={}, buf={}, bufSize={}, basep={}, io={}, LR={}", fd, buf, bufSize, basep, io, context.getLRPointer());
        }

        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        } else {
            buf.setSize(bufSize);
            return io.getdirentries64(buf, bufSize);
        }
    }

    private long flock(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int operation = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("flock fd={}, operation={}", fd, operation);
        }
        return 0;
    }

    private int fstatfs64(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer buf = context.getPointerArg(1);
        if (log.isDebugEnabled()) {
            log.debug("fstatfs64 fd={}, buf={}, LR={}", fd, buf, context.getLRPointer());
        }
        DarwinFileIO io = fdMap.get(fd);
        if (io != null) {
            if (verbose) {
                System.out.printf("File fstatfs '%s' from %s%n", io, emulator.getContext().getLRPointer());
            }
            return io.fstatfs(new StatFS(buf));
        }
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private long fchflags(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int flags = context.getIntArg(1);
        DarwinFileIO io = fdMap.get(fd);
        if (io != null) {
            int ret = io.chflags(flags);
            if (ret == -1) {
                log.info("fchflags fd={}, flags=0x{}", io, Integer.toHexString(flags));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("fchflags fd={}, flags=0x{}", io, Integer.toHexString(flags));
                }
            }
            return ret;
        } else {
            log.info("fchflags fd={}, flags=0x{}", io, Integer.toHexString(flags));
            Cpsr.getArm64(emulator.getBackend()).setCarry(true);
            return UnixEmulator.ENOENT;
        }
    }

    private long chflags(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        int flags = context.getIntArg(1);
        String pathname = path.getString(0);
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            int ret = result.io.chflags(flags);
            if (ret == -1) {
                log.info("chflags pathname={}, flags=0x{}", pathname, Integer.toHexString(flags));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("chflags pathname={}, flags=0x{}", pathname, Integer.toHexString(flags));
                }
            }
            return ret;
        } else {
            log.info("chflags pathname={}, flags=0x{}", pathname, Integer.toHexString(flags));
            Cpsr.getArm64(emulator.getBackend()).setCarry(true);
            return UnixEmulator.ENOENT;
        }
    }

    private int getppid(Emulator<?> emulator) {
        if (log.isDebugEnabled()) {
            log.debug("getppid");
        }
        return emulator.getPid();
    }

    private long pipe(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pipefd = context.getPointerArg(0);
        if (log.isDebugEnabled()) {
            int readfd = pipefd.getInt(0);
            int writefd = pipefd.getInt(4);
            log.debug("pipe readfd={}, writefd={}", readfd, writefd);
        }
        emulator.getMemory().setErrno(UnixEmulator.EFAULT);
        return -1;
    }

    private int stat64(Emulator<DarwinFileIO> emulator, int offset) {
        RegisterContext context = emulator.getContext();
        Pointer pathname = context.getPointerArg(offset);
        Pointer statbuf = context.getPointerArg(offset + 1);
        String path = FilenameUtils.normalize(pathname.getString(0), true);
        if (log.isDebugEnabled()) {
            log.debug("stat64 pathname={}, statbuf={}", path, statbuf);
        }
        return stat64(emulator, path, statbuf);
    }

    protected int stat64(Emulator<DarwinFileIO> emulator, String pathname, Pointer statbuf) {
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            if (verbose) {
                System.out.printf("File stat '%s' from %s%n", pathname, emulator.getContext().getLRPointer());
            }
            return result.io.fstat(emulator, new Stat64(statbuf));
        }

        int errno = result != null ? result.errno : UnixEmulator.ENOENT;
        if (verbose) {
            System.out.printf("File stat '%s' errno is %d from %s%n", pathname, errno, emulator.getContext().getLRPointer());
        }
        Cpsr.getArm64(emulator.getBackend()).setCarry(true);
        return errno;
    }

    private int write_NOCANCEL(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer buffer = context.getPointerArg(1);
        int count = context.getIntArg(2);
        return write(emulator, fd, buffer, count);
    }

    /**
     * lstat() is identical to stat(), except that if pathname is a symbolic link, then it returns information about the link itself, not the file that it refers to.
     */
    private int lstat(Emulator<DarwinFileIO> emulator, int offset) {
        RegisterContext context = emulator.getContext();
        Pointer pathname = context.getPointerArg(offset);
        Pointer stat = context.getPointerArg(offset + 1);
        String pathStr = pathname.getString(0);
        String path = FilenameUtils.normalize(pathStr, true);
        int ret = stat64(emulator, path, stat);
        if (log.isDebugEnabled()) {
            log.debug("lstat path={}, pathStr={}, stat={}, ret={}, LR={}", path, pathStr, stat, ret, context.getLRPointer());
        }
        return ret;
    }

    private int fstat(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer stat = context.getPointerArg(1);
        return fstat(emulator, fd, stat);
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
        if (verbose) {
            System.out.printf("File fstat '%s' from %s%n", file, emulator.getContext().getLRPointer());
        }
        return file.fstat(emulator, new Stat64(stat));
    }

    private static final int RLIMIT_NOFILE = 8;        /* number of open files */
    private static final int RLIMIT_POSIX_FLAG = 0x1000;    /* Set bit for strict POSIX */

    private long rlim_cur = 128;
    private long rlim_max = 256;

    private int getrlimit(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int resource = context.getIntArg(0);
        Pointer rlp = context.getPointerArg(1);
        boolean posix = (resource & RLIMIT_POSIX_FLAG) != 0;
        int type = resource & (RLIMIT_POSIX_FLAG - 1);
        String msg = "getrlimit resource=0x" + Integer.toHexString(resource) + ", rlp=" + rlp + ", posix=" + posix + ", type=" + type;
        if (type == RLIMIT_NOFILE) {
            RLimit rLimit = new RLimit(rlp);
            rLimit.rlim_cur = rlim_cur;
            rLimit.rlim_max = rlim_max;
            rLimit.pack();
            if (log.isDebugEnabled()) {
                msg += (", rLimit=" + rLimit);
                log.debug(msg);
            }
            return 0;
        } else {
            log.info(msg);
        }
        return 1;
    }

    private int setrlimit(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int resource = context.getIntArg(0);
        Pointer rlp = context.getPointerArg(1);
        boolean posix = (resource & RLIMIT_POSIX_FLAG) != 0;
        int type = resource & (RLIMIT_POSIX_FLAG - 1);
        String msg = "setrlimit resource=0x" + Integer.toHexString(resource) + ", rlp=" + rlp + ", posix=" + posix + ", type=" + type;
        if (type == RLIMIT_NOFILE) {
            RLimit rLimit = new RLimit(rlp);
            rLimit.unpack();
            rlim_cur = rLimit.rlim_cur;
            rlim_max = rLimit.rlim_max;
            if (log.isDebugEnabled()) {
                msg += (", rLimit=" + rLimit);
                log.debug(msg);
            }
            return 0;
        } else {
            log.info(msg);
        }
        return 1;
    }

    private long _kernelrpc_mach_port_mod_refs_trap(Emulator<?> emulator) {
        Arm64RegisterContext context = emulator.getContext();
        int task = context.getXInt(0);
        int name = context.getXInt(1);
        int right = context.getXInt(2);
        int delta = context.getXInt(3);
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_mod_refs_trap task={}, name={}, right={}, delta={}", task, name, right, delta);
        }
        if (verbose) {
            System.out.printf("mach_port_mod_refs %d with right=0x%x from %s%n", name, right, emulator.getContext().getLRPointer());
        }
        return 0;
    }

    private int _kernelrpc_mach_port_insert_right_trap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int task = context.getIntArg(0);
        int name = context.getIntArg(1);
        int poly = context.getIntArg(2);
        int polyPoly = context.getIntArg(3);
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_insert_right_trap task={}, name={}, poly={}, polyPoly={}", task, name, poly, polyPoly);
        }
        if (verbose) {
            System.out.printf("mach_port_insert_right %d with poly=0x%x from %s%n", name, poly, emulator.getContext().getLRPointer());
        }
        return 0;
    }

    private int _kernelrpc_mach_port_construct_trap(Emulator<?> emulator) {
        Arm64RegisterContext context = emulator.getContext();
        int task = context.getXInt(0);
        Pointer options = context.getXPointer(1);
        long ctx = context.getXInt(2);
        Pointer name = context.getXPointer(3);
        if (log.isDebugEnabled()) {
            MachPortOptions portOptions = new MachPortOptions(options);
            portOptions.unpack();
            log.debug("_kernelrpc_mach_port_construct_trap task={}, options={}, context=0x{}, name={}, portOptions={}", task, options, Long.toHexString(ctx), name, portOptions);
        }
        name.setInt(0, 0x88);
        if (verbose) {
            System.out.printf("mach_port_construct %d from %s%n", 0x88, emulator.getContext().getLRPointer());
        }
        return 0;
    }

    private long getaudit_addr(Emulator<?> emulator) {
        Arm64RegisterContext context = emulator.getContext();
        Pointer addr = context.getXPointer(0);
        int size = context.getXInt(1);
        if (log.isDebugEnabled()) {
            log.debug("getaudit_addr={}, size={}", addr, size);
        }
        return 0;
    }

    private static final int PROC_INFO_CALL_SETCONTROL = 0x5;
    private static final int PROC_SELFSET_THREADNAME = 2;

    private static final int PROC_INFO_CALL_PIDINFO = 0x2;
    private static final int PROC_PIDPATHINFO = 11;
    private static final int PROC_PIDT_SHORTBSDINFO = 13;

    private int proc_info(Emulator<?> emulator, int index) {
        RegisterContext context = emulator.getContext();
        int callNum = context.getIntArg(index);
        int pid = context.getIntArg(index + 1);
        int flavor = context.getIntArg(index + 2);
        long arg = context.getLongArg(index + 3);
        Pointer buffer = context.getPointerArg(index + 4);
        int bufferSize = context.getIntArg(index + 5);

        String executable = executableBundlePath;
        if (executable == null) {
            executable = emulator.getProcessName();
        }
        String msg = "proc_info callNum=" + callNum + ", pid=" + pid + ", flavor=" + flavor + ", arg=" + arg + ", buffer=" + buffer + ", bufferSize=" + bufferSize;
        if (PROC_INFO_CALL_SETCONTROL == callNum && PROC_SELFSET_THREADNAME == flavor) {
            String threadName = buffer.getString(0);
            if (log.isDebugEnabled()) {
                log.debug("{}, newName={}", msg, threadName);
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
        } else if (PROC_INFO_CALL_PIDINFO == callNum && PROC_PIDPATHINFO == flavor && executable != null) {
            byte[] data = executable.getBytes(StandardCharsets.UTF_8);
            if (bufferSize < data.length + 1) {
                throw new UnsupportedOperationException();
            }
            buffer.write(0, Arrays.copyOf(data, data.length + 1), 0, data.length + 1);
            return 0;
        } else {
            log.info(msg);
            Logger log = LoggerFactory.getLogger(AbstractEmulator.class);
            if (log.isDebugEnabled()) {
                emulator.attach().debug();
            }
            return -1;
        }
    }

    protected int semwait_signal(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int cond_sem = context.getIntArg(0);
        int mutex_sem = context.getIntArg(1);
        int timeout = context.getIntArg(2);
        int relative = context.getIntArg(3);
        long tv_sec = context.getLongArg(4);
        int tv_nsec = context.getIntArg(5);
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

    private int sandbox_ms(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer policyName = context.getPointerArg(0);
        int call = context.getIntArg(1);
        Pointer args = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("sandbox_ms policyName={}, call={}, args={}", policyName.getString(0), call, args);
        }
        return 0;
    }

    private int issetugid() {
        log.debug("issetugid");
        return 0;
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

    private long bsdthread_create(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        UnidbgPointer start_routine = context.getPointerArg(0);
        UnidbgPointer arg = context.getPointerArg(1);
        UnidbgPointer stack = context.getPointerArg(2);
        UnidbgPointer thread = context.getPointerArg(3);
        int flags = context.getIntArg(4);

        return bsdthread_create(emulator, start_routine, arg, stack, thread, flags);
    }

    private int bsdthread_register(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        UnidbgPointer thread_start = context.getPointerArg(0);
        UnidbgPointer start_wqthread = context.getPointerArg(1);
        int pthreadSize = context.getIntArg(2);
        UnidbgPointer data = context.getPointerArg(3);
        int dataSize = context.getIntArg(4);
        long offset = context.getLongArg(5);
        if (log.isDebugEnabled()) {
            log.debug("bsdthread_register thread_start={}, start_wqthread={}, pthreadSize={}, data={}, dataSize={}, offset=0x{}", thread_start, start_wqthread, pthreadSize, data, dataSize, Long.toHexString(offset));
        }
        return bsdthread_register(thread_start, pthreadSize);
    }

    private int readlink(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer pathname = context.getPointerArg(0);
        Pointer buf = context.getPointerArg(1);
        int bufSize = context.getIntArg(2);
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

    private int munmap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        long timeInMillis = System.currentTimeMillis();
        long start = context.getLongArg(0);
        int length = context.getIntArg(1);
        emulator.getMemory().munmap(start, length);
        if (log.isDebugEnabled()) {
            log.debug("munmap start=0x{}, length={}, offset={}", Long.toHexString(start), length, System.currentTimeMillis() - timeInMillis);
        }
        return 0;
    }

    private int sysctl(Emulator<?> emulator, int offset) {
        RegisterContext context = emulator.getContext();
        Pointer name = context.getPointerArg(offset);
        int namelen = context.getIntArg(offset + 1);
        Pointer buffer = context.getPointerArg(offset + 2);
        Pointer bufferSize = context.getPointerArg(offset + 3);
        Pointer set0 = context.getPointerArg(offset + 4);
        int set1 = context.getIntArg(offset + 5);

        int top = name.getInt(0);
        switch (top) {
            case CTL_UNSPEC:
                int action = name.getInt(4);
                if (action == 3) {
                    byte[] bytes = set0.getByteArray(0, set1);
                    String sub = new String(bytes, StandardCharsets.UTF_8);
                    if (log.isDebugEnabled()) {
                        log.debug("sysctl CTL_UNSPEC action={}, namelen={}, buffer={}, bufferSize={}, sub={}, set1={}", action, namelen, buffer, bufferSize, sub, set1);
                    }
                    switch (sub) {
                        case "unidbg.debug":
                            return verbose || LoggerFactory.getLogger("com.github.unidbg.ios.debug").isDebugEnabled() ? 1 : 0;
                        case "kern.ostype":
                            buffer.setInt(0, CTL_KERN);
                            buffer.setInt(4, KERN_OSTYPE);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "kern.osrelease":
                            buffer.setInt(0, CTL_KERN);
                            buffer.setInt(4, KERN_OSRELEASE);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "kern.version":
                            buffer.setInt(0, CTL_KERN);
                            buffer.setInt(4, KERN_VERSION);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "kern.osversion":
                            buffer.setInt(0, CTL_KERN);
                            buffer.setInt(4, KERN_OSVERSION);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "kern.boottime":
                            buffer.setInt(0, CTL_KERN);
                            buffer.setInt(4, KERN_BOOTTIME);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "hw.machine":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_MACHINE);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "hw.model":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_MODEL);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "hw.cputype":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_CPU_TYPE);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "hw.cpusubtype":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_CPU_SUBTYPE);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "hw.cpufamily":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_CPU_FAMILY);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "hw.ncpu":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_NCPU);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "hw.memsize":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_MEMSIZE);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "hw.physicalcpu_max":
                        case "hw.logicalcpu_max":
                            buffer.setInt(0, CTL_HW);
                            buffer.setInt(4, HW_CPU_MAX);
                            bufferSize.setLong(0, 8);
                            return 0;
                        case "sysctl.proc_native":
                            return -1;
                    }
                    if (log.isDebugEnabled()) {
                        createBreaker(emulator).debug();
                    }
                    log.info("sysctl CTL_UNSPEC action={}, namelen={}, buffer={}, bufferSize={}, sub={}", action, namelen, buffer, bufferSize, sub);
                    return -1;
                }
                log.info("sysctl CTL_UNSPEC action={}, namelen={}, buffer={}, bufferSize={}, set0={}, set1={}", action, namelen, buffer, bufferSize, set0, set1);
                break;
            case CTL_KERN: {
                action = name.getInt(4);
                String msg = "sysctl CTL_KERN action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1;
                switch (action) {
                    case KERN_USRSTACK32:
                    case KERN_PROCARGS2:
                        log.info(msg);
                        return 1;
                    case KERN_OSTYPE:
                        log.debug(msg);
                        String osType = getKernelOsType();
                        if (bufferSize != null) {
                            bufferSize.setLong(0, osType.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, osType);
                        }
                        return 0;
                    case KERN_OSRELEASE:
                        log.debug(msg);
                        String osRelease = getKernelOsRelease();
                        if (bufferSize != null) {
                            bufferSize.setLong(0, osRelease.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, osRelease);
                        }
                        return 0;
                    case KERN_VERSION:
                        log.debug(msg);
                        String version = getKernelVersion();
                        if (bufferSize != null) {
                            bufferSize.setLong(0, version.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, version);
                        }
                        return 0;
                    case KERN_ARGMAX:
                        bufferSize.setLong(0, 4);
                        buffer.setInt(0, 128);
                        return 0;
                    case KERN_PROC:
                        int subType = name.getInt(8);
                        if (subType == KERN_PROC_PID) {
                            if (bufferSize != null) {
                                bufferSize.setLong(0, UnidbgStructure.calculateSize(KInfoProc64.class));
                            }
                            KInfoProc64 kInfoProc = null;
                            if (buffer != null) {
                                kInfoProc = new KInfoProc64(buffer);
                                kInfoProc.unpack();

                                kInfoProc.kp_proc.p_flag = 0; // P_TRACED
                                kInfoProc.kp_eproc.e_ucred.cr_uid = 0;
                                kInfoProc.pack();
                            }
                            int pid = name.getInt(0xc);
                            log.debug("{}, subType={}, pid={}, kInfoProc={}", msg, subType, pid, kInfoProc);
                            return 0;
                        }
                        log.info("{}, subType={}", msg, subType);
                        break;
                    case KERN_OSVERSION:
                        log.debug(msg);
                        String osVersion = getBuildVersion();
                        if (bufferSize != null) {
                            bufferSize.setLong(0, osVersion.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, osVersion);
                        }
                        return 0;
                    case KERN_HOSTNAME:
                        log.debug(msg);
                        String hostName = getKernelHostName();
                        if (bufferSize != null) {
                            bufferSize.setLong(0, hostName.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, hostName);
                        }
                        return 0;
                    case KERN_USRSTACK64:
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 8);
                        }
                        if (buffer != null) {
                            buffer.setLong(0, emulator.getMemory().getStackBase());
                        }
                        return 0;
                    case KERN_BOOTTIME:
                        if (bufferSize != null) {
                            bufferSize.setLong(0, UnidbgStructure.calculateSize(TimeVal64.class));
                        }
                        if (buffer != null) {
                            fillKernelBootTime(buffer);
                        }
                        return 0;
                    case KERN_MAXFILESPERPROC:
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, 256);
                        }
                        return 0;
                    default:
                        log.info(msg);
                        if (log.isDebugEnabled()) {
                            createBreaker(emulator).debug();
                        }
                        break;
                }
                break;
            }
            case CTL_HW: {
                action = name.getInt(4);
                String msg = "sysctl CTL_HW action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1;
                switch (action) {
                    case HW_MACHINE:
                        log.debug(msg);
                        String machine = getHwMachine();
                        if (bufferSize != null) {
                            bufferSize.setLong(0, machine.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, machine);
                        }
                        return 0;
                    case HW_MODEL:
                        log.debug(msg);
                        String model = "N53AP";
                        if (bufferSize != null) {
                            bufferSize.setLong(0, model.length() + 1);
                        }
                        if (buffer != null) {
                            buffer.setString(0, model);
                        }
                        return 0;
                    case HW_NCPU:
                        log.debug(msg);
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, getHwNcpu()); // 2 cpus
                        }
                        return 0;
                    case HW_PAGESIZE:
                        log.debug(msg);
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, emulator.getPageAlign());
                        }
                        return 0;
                    case HW_CPU_TYPE:
                        log.debug(msg);
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, CPU_TYPE_ARM);
                        }
                        return 0;
                    case HW_CPU_SUBTYPE:
                        log.debug(msg);
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, CPU_SUBTYPE_ARM_V7);
                        }
                        return 0;
                    case HW_CPU_FAMILY:
                        log.debug(msg);
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, 933271106);
                        }
                        return 0;
                    case HW_MEMSIZE:
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 8);
                        }
                        if (buffer != null) {
                            long memSize = 2L * 1024 * 1024 * 1024; // 2G
                            buffer.setLong(0, memSize);
                        }
                        return 0;
                    case HW_CPU_FREQ:
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, 1800000000);
                        }
                        return 0;
                    case HW_CPU_MAX:
                    case HW_AVAILCPU:
                        if (bufferSize != null) {
                            bufferSize.setLong(0, 4);
                        }
                        if (buffer != null) {
                            buffer.setInt(0, getHwNcpu());
                        }
                        return 0;
                }
                log.info(msg);
                break;
            }
            case CTL_NET:
                action = name.getInt(4); // AF_ROUTE
                String msg = "sysctl CTL_NET action=" + action + ", namelen=" + namelen + ", buffer=" + buffer + ", bufferSize=" + bufferSize + ", set0=" + set0 + ", set1=" + set1;
                int family = name.getInt(0xc); // AF_INET
                int rt = name.getInt(0x10);
                if(action == AF_ROUTE && rt == NET_RT_IFLIST) {
                    log.debug(msg);
                    try {
                        List<DarwinUtils.NetworkIF> networkIFList = DarwinUtils.getNetworkIFs(isVerbose());
                        int sizeOfSDL = UnidbgStructure.calculateSize(SockAddrDL.class);
                        int entrySize = UnidbgStructure.calculateSize(IfMsgHeader.class) + sizeOfSDL;
                        if (bufferSize != null) {
                            bufferSize.setLong(0, (long) entrySize * networkIFList.size());
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
        return 1;
    }

    @Override
    protected void fillKernelBootTime(Pointer buffer) {
        long currentTimeMillis = bootTime;
        long tv_sec = currentTimeMillis / 1000;
        long tv_usec = (currentTimeMillis % 1000) * 1000 + (bootTime / 7 % 1000);
        TimeVal64 timeVal = new TimeVal64(buffer);
        timeVal.tv_sec = tv_sec;
        timeVal.tv_usec = tv_usec;
        timeVal.pack();
    }

    private long open_dprotected_np(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        int flags = context.getIntArg(1);
        int _class = context.getIntArg(2);
        int dpflags = context.getIntArg(3);
        int mode = context.getIntArg(4);
        String pathname = path.getString(0);
        int fd = open(emulator, pathname, flags);
        if (log.isDebugEnabled()) {
            log.debug("open_dprotected_np path={}, flags=0x{}, class={}, dpflags=0x{}, mode=0x{}", pathname, Integer.toHexString(flags), _class, Integer.toHexString(dpflags), Integer.toHexString(mode));
        }
        return fd;
    }

    private long getattrlist(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        Pointer attrListPointer = context.getPointerArg(1);
        UnidbgPointer attrBuf = context.getPointerArg(2);
        int attrBufSize = context.getIntArg(3);
        int options = context.getIntArg(4);
        String pathname = path.getString(0);
        AttrList attrList = new AttrList(attrListPointer);
        attrBuf.setSize(attrBufSize);

        String msg = "getattrlist path=" + pathname + ", attrList=" + attrList + ", attrBuf=" + attrBuf + ", attrBufSize=" + attrBufSize + ", options=0x" + Integer.toHexString(options);
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            int ret = result.io.getattrlist(attrList, attrBuf, attrBufSize);
            if (ret != 0) {
                log.info("{}, ret={}", msg, ret);
                if (log.isDebugEnabled() || LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
                    createBreaker(emulator).debug();
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("{}, ret={}", msg, ret);
                }
            }
            return ret;
        }

        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.EEXIST);
        return -1;
    }

    private long setattrlist(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        Pointer attrListPointer = context.getPointerArg(1);
        UnidbgPointer attrBuf = context.getPointerArg(2);
        int attrBufSize = context.getIntArg(3);
        int options = context.getIntArg(4);
        String pathname = path.getString(0);
        AttrList attrList = new AttrList(attrListPointer);
        attrBuf.setSize(attrBufSize);

        String msg = "setattrlist path=" + pathname + ", attrList=" + attrList + ", attrBuf=" + attrBuf + ", attrBufSize=" + attrBufSize + ", options=0x" + Integer.toHexString(options);
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            int ret = result.io.setattrlist(attrList, attrBuf, attrBufSize);
            if (ret != 0) {
                log.info("{}, ret={}", msg, ret);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("{}, ret={}, result={}", msg, ret, result);
                }
            }
            return ret;
        }

        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.EACCES);
        log.info(msg);
        return -1;
    }

    private long getxattr(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        Pointer name = context.getPointerArg(1);
        UnidbgPointer value = context.getPointerArg(2);
        int size = context.getIntArg(3);
        int position = context.getIntArg(4);
        int options = context.getIntArg(5);
        String pathname = path.getString(0);
        if (position != 0 || (options & XATTR_CREATE) != 0 || (options & XATTR_REPLACE) != 0) {
            log.info("getxattr path={}, name={}, value={}, size={}, position={}, options=0x{}", pathname, name.getString(0), value, size, position, Integer.toHexString(options));
            return -1;
        }
        if (value != null) {
            value.setSize(size);
        }
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            int ret = result.io.getxattr(emulator, name.getString(0), value, size);
            if (ret == -1) {
                log.info("getxattr path={}, name={}, value={}, size={}, position={}, options=0x{}", pathname, name.getString(0), value, size, position, Integer.toHexString(options));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("getxattr path={}, name={}, value={}, size={}, position={}, options=0x{}", pathname, name.getString(0), value, size, position, Integer.toHexString(options));
                }
            }
            return ret;
        } else {
            log.info("getxattr path={}, name={}, value={}, size={}, position={}, options=0x{}", pathname, name.getString(0), value, size, position, Integer.toHexString(options));
            emulator.getMemory().setErrno(UnixEmulator.ENOENT);
            return -1;
        }
    }

    private long removexattr(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        Pointer name = context.getPointerArg(1);
        int options = context.getIntArg(2);
        String pathname = path.getString(0);
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            int ret = result.io.removexattr(name.getString(0));
            if (ret == -1) {
                log.info("removexattr path={}, name={}, options=0x{}", pathname, name.getString(0), Integer.toHexString(options));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("removexattr path={}, name={}, options=0x{}", pathname, name.getString(0), Integer.toHexString(options));
                }
            }
            return ret;
        } else {
            log.info("removexattr path={}, name={}, options=0x{}, result={}", pathname, name.getString(0), Integer.toHexString(options), result);
            emulator.getMemory().setErrno(UnixEmulator.ENOENT);
            return -1;
        }
    }

    private long setxattr(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer path = context.getPointerArg(0);
        Pointer name = context.getPointerArg(1);
        Pointer value = context.getPointerArg(2);
        int size = context.getIntArg(3);
        int position = context.getIntArg(4);
        int options = context.getIntArg(5);
        String pathname = path.getString(0);
        if (position != 0 || (options & XATTR_CREATE) != 0 || (options & XATTR_REPLACE) != 0) {
            log.info("setxattr path={}, name={}, value={}, size={}, position={}, options=0x{}", pathname, name.getString(0), value, size, position, Integer.toHexString(options));
            return -1;
        }
        FileResult<DarwinFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            int ret = result.io.setxattr(name.getString(0), value.getByteArray(0, size));
            if (ret == -1) {
                log.info("setxattr path={}, name={}, value={}, size={}, position={}, options=0x{}", pathname, name.getString(0), value, size, position, Integer.toHexString(options));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("setxattr path={}, name={}, value={}, size={}, position={}, options=0x{}", pathname, name.getString(0), value, size, position, Integer.toHexString(options));
                }
            }
            return ret;
        } else {
            log.info("setxattr path={}, name={}, value={}, size={}, position={}, options=0x{}", pathname, name.getString(0), value, size, position, Integer.toHexString(options));
            Cpsr.getArm64(emulator.getBackend()).setCarry(true);
            return UnixEmulator.ENOENT;
        }
    }

    private long fsetxattr(Emulator<DarwinFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer name = context.getPointerArg(1);
        Pointer value = context.getPointerArg(2);
        int size = context.getIntArg(3);
        int position = context.getIntArg(4);
        int options = context.getIntArg(5);
        DarwinFileIO io = fdMap.get(fd);
        if (position != 0 || (options & XATTR_CREATE) != 0 || (options & XATTR_REPLACE) != 0) {
            log.info("fsetxattr fd={}, name={}, value={}, size={}, position={}, options=0x{}", fd, name.getString(0), value, size, position, Integer.toHexString(options));
            return -1;
        }
        if (io != null) {
            int ret = io.setxattr(name.getString(0), value.getByteArray(0, size));
            if (ret == -1) {
                log.info("fsetxattr fd={}, name={}, value={}, size={}, position={}, options=0x{}", fd, name.getString(0), value, size, position, Integer.toHexString(options));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("fsetxattr fd={}, name={}, value={}, size={}, position={}, options=0x{}", fd, name.getString(0), value, size, position, Integer.toHexString(options));
                }
            }
            return ret;
        }
        log.info("fsetxattr fd={}, name={}, value={}, size={}, position={}, options=0x{}", fd, name.getString(0), value, size, position, Integer.toHexString(options));
        return 0;
    }

    private int _kernelrpc_mach_vm_deallocate_trap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int target = context.getIntArg(0);
        long address = context.getLongArg(1);
        long size = context.getLongArg(2);

        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_deallocate_trap target={}, address=0x{}, size=0x{}", target, Long.toHexString(address), Long.toHexString(size));
        } else {
            Logger log = LoggerFactory.getLogger("com.github.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug("_kernelrpc_mach_vm_deallocate_trap target=" + target + ", address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", lr=" + context.getLRPointer());
            }
        }
        if (size > 0) {
            emulator.getMemory().munmap(address, (int) size);
        }
        return 0;
    }

    private int _kernelrpc_mach_vm_protect_trap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int target = context.getIntArg(0);
        long address = context.getLongArg(1);
        long size = context.getLongArg(2);
        int set_maximum = context.getIntArg(3);
        int new_protection = context.getIntArg(4);
        long alignedLength = ARM.alignSize(size, emulator.getPageAlign());
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_protect_trap target={}, address=0x{}, size=0x{}, set_maximum={}, new_protection=0x{}", target, Long.toHexString(address), Long.toHexString(size), set_maximum, Integer.toHexString(new_protection));
        }
        if (address % emulator.getPageAlign() != 0) {
            throw new UnsupportedOperationException("address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size));
        }
        return emulator.getMemory().mprotect(address, (int) alignedLength, new_protection);
    }

    private int _kernelrpc_mach_vm_map_trap(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int target = context.getIntArg(0);
        Pointer address = context.getPointerArg(1);
        long size = context.getLongArg(2);
        long mask = context.getLongArg(3);
        int flags = context.getIntArg(4);
        int cur_protection = context.getIntArg(5);
        int tag = flags >> 24;
        boolean anywhere = (flags & MachO.VM_FLAGS_ANYWHERE) != 0;
        if (!anywhere) {
            throw new BackendException("_kernelrpc_mach_vm_map_trap fixed");
        }

        MachOLoader loader = (MachOLoader) emulator.getMemory();
        Pointer value = address.getPointer(0);
        UnidbgPointer pointer;
        if (mask != 0) {
            pointer = UnidbgPointer.pointer(emulator, loader.allocate(size, mask));
        } else {
            pointer = loader.mmap((int) size, cur_protection);
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
        RegisterContext context = emulator.getContext();
        int target = context.getIntArg(0);
        Pointer address = context.getPointerArg(1);
        long size = context.getLongArg(2);
        int flags = context.getIntArg(3);
        int tag = flags >> 24;
        boolean anywhere = (flags & MachO.VM_FLAGS_ANYWHERE) != 0;
        if (!anywhere) {
            long start = address.getLong(0);
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
                log.debug("_kernelrpc_mach_vm_allocate_trap fixed, address={}, size={}, flags=0x{}, anywhere=false", pointer, size, Integer.toHexString(flags));
            }
            return 0;
        }

        Pointer value = address.getPointer(0);
        UnidbgPointer pointer = emulator.getMemory().mmap((int) size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);
        pointer.write(0, new byte[(int) size], 0, (int) size);
        address.setPointer(0, pointer);
        String msg = "_kernelrpc_mach_vm_allocate_trap target=" + target + ", address=" + address + ", value=" + value + ", size=0x" + Long.toHexString(size) + ", flags=0x" + Integer.toHexString(flags) + ", pointer=" + pointer + ", anywhere=true, tag=0x" + Integer.toHexString(tag);
        if (log.isDebugEnabled()) {
            log.debug(msg);
        } else {
            Logger log = LoggerFactory.getLogger("com.github.unidbg.ios.malloc");
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
        }
        return 0;
    }

    private int _kernelrpc_mach_port_deallocate_trap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int task = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        int name = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_port_deallocate_trap task={}, name={}", task, name);
        }
        if (verbose) {
            System.out.printf("mach_port_deallocate %d from %s%n", name, emulator.getContext().getLRPointer());
        }
        return 0;
    }

    private int _workq_open(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        if (log.isDebugEnabled()) {
            log.debug("_workq_open LR={}", context.getLRPointer());
        }
        if (LoggerFactory.getLogger(AbstractEmulator.class).isTraceEnabled()) {
            createBreaker(emulator).debug();
        }
        return 0;
    }

    private int _workq_kernreturn(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int options = context.getIntArg(0);
        Pointer item = context.getPointerArg(1);
        int arg2 = context.getIntArg(2);
        int arg3 = context.getIntArg(3);
        if (log.isDebugEnabled()) {
            log.debug("_workq_kernreturn options=0x{}, item={}, arg2={}, arg3=0x{}, LR={}", Integer.toHexString(options), item, arg2, Integer.toHexString(arg3), context.getLRPointer());
        }
        if (LoggerFactory.getLogger(AbstractEmulator.class).isTraceEnabled()) {
            createBreaker(emulator).debug();
        }
        return 0;
    }

    // https://github.com/lunixbochs/usercorn/blob/master/go/kernel/mach/ports.go
    private int mach_msg_trap(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        RegisterContext context = emulator.getContext();
        UnidbgPointer msg = context.getPointerArg(0);
        int option = context.getIntArg(1);
        int send_size = context.getIntArg(2);
        int rcv_size = context.getIntArg(3);
        int rcv_name = context.getIntArg(4);
        int timeout = context.getIntArg(5);
        int notify = context.getIntArg(6);

        msg.setSize(Math.max(send_size, rcv_size));

        final MachMsgHeader header = new MachMsgHeader(msg);
        header.unpack();
        if (log.isDebugEnabled()) {
            log.debug("mach_msg_trap msg={}, option=0x{}, send_size={}, rcv_size={}, rcv_name={}, timeout={}, notify={}, LR={}, header={}", msg, Integer.toHexString(option), send_size, rcv_size, rcv_name, timeout, notify, context.getLRPointer(), header);
        }

        final UnidbgPointer request = (UnidbgPointer) msg.share(header.size());

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
                    if (verbose) {
                        System.out.printf("task_get_special_port %d from %s%n", BOOTSTRAP_PORT, emulator.getContext().getLRPointer());
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
            case 4807: // vm_copy
            {
                VmCopy64Request args = new VmCopy64Request(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_copy args={}, lr={}", args, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
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
                    log.debug("_kernelrpc_mach_vm_remap args={}, lr={}", args, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
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
            case 4815: // vm_region_recurse_64
            {
                VmRegionRecurse64Request args = new VmRegionRecurse64Request(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_region_recurse_64 args={}", args);
                }

                VmRegionRecurse64Reply reply = new VmRegionRecurse64Reply(request);
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

                if (memoryMap == null) {
                    break;
                }

                reply.NDR = args.NDR;
                reply.retCode = 0; // success
                reply.addressLow = (int) memoryMap.base;
                reply.addressHigh = (int) (memoryMap.base >> 32L);
                reply.sizeLow = (int) memoryMap.size;
                reply.sizeHigh = (int) (memoryMap.size >> 32L);
                reply.infoCnt = 7;
                reply.nestingDepth = args.nestingDepth;
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
                    log.debug("task_set_exception_ports args={}, lr={}", args, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
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
                    log.debug("task_get_exception_ports args={}, lr={}", args, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
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
                    log.debug("task_get_exception_ports reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3404: // mach_ports_lookup
            {
                MachPortsLookupReply64 reply = new MachPortsLookupReply64(request);
                reply.unpack();

                header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                header.msgh_size = 56;
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.retCode = 1;
                reply.outPortLow = (int) request.toUIntPeer();
                reply.outPortHigh = (int) (request.peer >> 32L);
                reply.mask = 0x2110000;
                reply.cnt = 0;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("mach_ports_lookup reply={}", reply);
                }
                if (verbose) {
                    System.out.printf("mach_ports_lookup from %s%n", emulator.getContext().getLRPointer());
                }
                return MACH_MSG_SUCCESS;
            }
            case 404: { // vproc_mig_look_up2
                return vproc_mig_look_up2(request, header);
            }
            case 78945669: { // notify_server_register_plain
                NotifyServerRegisterPlain64Request args = new NotifyServerRegisterPlain64Request(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    Pointer pointer = UnidbgPointer.pointer(emulator, args.nameLow | (long) args.nameHigh << 32L);
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
                NotifyServerRegisterCheck64Request args = new NotifyServerRegisterCheck64Request(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    Pointer pointer = UnidbgPointer.pointer(emulator, (args.nameLow & 0xffffffffL) | (long) args.nameHigh << 32L);
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
                NotifyServerRegisterMachPort64Request args = new NotifyServerRegisterMachPort64Request(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    Pointer pointer = UnidbgPointer.pointer(emulator, args.nameLow | (long) args.nameHigh << 32L);
                    log.debug("notify_server_register_mach_port args={}, name={}", args, pointer == null ? null : new String(pointer.getByteArray(0, args.namelen), StandardCharsets.UTF_8));
                }

                NotifyServerRegisterMachPortReply reply = new NotifyServerRegisterMachPortReply(request);
                reply.unpack();

                header.setMsgBits(false);
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
            case 3201: { // _kernelrpc_mach_port_type
                MachPortTypeRequest args = new MachPortTypeRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("_kernelrpc_mach_port_type args={}", args);
                }

                MachPortTypeReply reply = new MachPortTypeReply(request);
                reply.unpack();

                header.setMsgBits(false);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.retCode = 0;
                reply.ptype = 0x70000;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("_kernelrpc_mach_port_set_attributes reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 2868: { // io_service_add_notification
                IOServiceAddNotificationRequest args = new IOServiceAddNotificationRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("io_service_add_notification args={}, matching={}", args, args.getMatching());
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
                    log.debug("io_service_add_notification reply={}", reply);
                }
                return MACH_MSG_SUCCESS;
            }
            case 4816: { // vm_region_64
                VmRegion64Request args = new VmRegion64Request(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_region_64 args={}", args);
                }
                if (args.flavor != VmRegion64Request.VM_REGION_BASIC_INFO_64) {
                    throw new UnsupportedOperationException("flavor=" + args.flavor);
                }

                VmRegion64Reply reply = new VmRegion64Reply(request);
                reply.unpack();

                header.setMsgBits(true);
                header.msgh_size = header.size() + reply.size();
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
                    reply.retCode1 = 1;
                    reply.pack();

                    if (log.isDebugEnabled()) {
                        log.debug("vm_region_64 reply={}", reply);
                    }
                    return MACH_MSG_SUCCESS;
                }

                reply.NDR.mig_vers = 1;
                reply.NDR.int_rep = 0;
                reply.retCode2 = 0x110000;
                reply.outCnt = VmRegion64Request.VM_REGION_BASIC_INFO_COUNT_64;
                reply.address = memoryRegion.base;
                reply.size = memoryRegion.size;
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
                    log.debug("vm_region_64 reply={}", reply);
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
                if (args.flavor == TaskInfoRequest.TASK_VM_INFO) {
                    TaskVmInfoReply64 reply = new TaskVmInfoReply64(request);
                    reply.unpack();

                    header.setMsgBits(false);
                    header.msgh_size = header.size() + reply.size();
                    header.msgh_remote_port = header.msgh_local_port;
                    header.msgh_local_port = 0;
                    header.msgh_id += 100; // reply Id always equals reqId+100
                    header.pack();

                    reply.retCode = 0;
                    reply.task_info_outCnt = UnidbgStructure.calculateSize(TaskVmInfo64.class) / 4;
                    reply.vmInfo.virtual_size = 0x100000000L;
                    reply.vmInfo.region_count = emulator.getMemory().getMemoryMap().size();
                    reply.vmInfo.page_size = emulator.getPageAlign();
                    reply.pack();

                    if (log.isDebugEnabled()) {
                        log.debug("task_info TASK_VM_INFO reply={}", reply);
                    }
                    return MACH_MSG_SUCCESS;
                }
                if (args.flavor == TaskInfoRequest.TASK_BASIC_INFO_64_2) {
                    TaskBasicInfoReply64V2 reply = new TaskBasicInfoReply64V2(request);
                    reply.unpack();

                    header.setMsgBits(false);
                    header.msgh_size = header.size() + reply.size();
                    header.msgh_remote_port = header.msgh_local_port;
                    header.msgh_local_port = 0;
                    header.msgh_id += 100; // reply Id always equals reqId+100
                    header.pack();

                    reply.retCode = 0;
                    reply.task_info_outCnt = UnidbgStructure.calculateSize(TaskBasicInfoReply64V2.class) / 4;
                    // get usage size;
                    reply.basicInfo.suspendCount = 0;
                    // 1gb
                    reply.basicInfo.virtualSize = 1024 * 1024 * 1024;
                    // 100m
                    reply.basicInfo.residentSize = 100 * 1024 * 1024;
                    //
                    reply.basicInfo.userTime = 0;
                    reply.basicInfo.systemTime = 0;
                    reply.pack();

                    if (log.isDebugEnabled()) {
                        log.debug("task_info TASK_BASIC_INFO_64_2 reply={}", reply);
                    }
                    return MACH_MSG_SUCCESS;
                }
                log.warn("task_info flavor={}", args.flavor);
                if (LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
                    createBreaker(emulator).debug();
                }
                return -1;
            }
            case 78: { // _dispatch_send_wakeup_runloop_thread
                if (log.isDebugEnabled()) {
                    log.debug("_dispatch_send_wakeup_runloop_thread");
                }
                return MACH_MSG_SUCCESS;
            }
            case 3402: { // task_threads
                TaskThreadsReply64 reply = new TaskThreadsReply64(request);
                reply.unpack();

                header.setMsgBits(true);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.body.msgh_descriptor_count = 1;
                reply.act_list = UnidbgPointer.nativeValue(request);
                reply.mask = 0x2110000;
                reply.act_listCnt = 0;
                reply.pack();

                log.debug("task_threads reply={}", reply);
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
            case 4808: // vm_read_overwrite
            {
                VmReadOverwriteRequest args = new VmReadOverwriteRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_read_overwrite args={}, lr={}", args, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }

                byte[] data = backend.mem_read(args.address, args.size);
                emulator.getMemory().pointer(args.data).write(data);

                VmReadOverwriteReply reply = new VmReadOverwriteReply(request);
                reply.unpack();

                header.msgh_bits &= 0xff;
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.retCode = 0;
                reply.NDR = args.NDR;
                reply.outSize = args.size;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("vm_read_overwrite reply={}, header={}", reply, header);
                }
                return MACH_MSG_SUCCESS;
            }
            case 3603: { // _thread_get_state
                ThreadStateRequest args = new ThreadStateRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("_thread_get_state args={}", request);
                }

                ThreadStateReply64 reply = new ThreadStateReply64(request);
                reply.unpack();
                header.setMsgBits(false);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                if (args.flavor != ThreadStateRequest.ARM_THREAD_STATE64) {
                    reply.retCode = 4;
                    reply.pack();
                    if (log.isDebugEnabled()) {
                        log.debug("_thread_get_state reply={}", reply);
                    }
                    return MACH_MSG_SUCCESS;
                }

                reply.retCode = 0;
                reply.outCnt = ThreadStateRequest.ARM_THREAD_STATE64_COUNT;
                for (int reg = Arm64Const.UC_ARM64_REG_X0; reg <= Arm64Const.UC_ARM64_REG_X28; reg++) {
                    reply.state.__x[reg - Arm64Const.UC_ARM64_REG_X0] = backend.reg_read(reg).longValue();
                }
                reply.state.__fp = backend.reg_read(Arm64Const.UC_ARM64_REG_FP).longValue();
                reply.state.__lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
                reply.state.__sp = backend.reg_read(Arm64Const.UC_ARM64_REG_SP).longValue();
                reply.state.__pc = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                reply.state.__cpsr = backend.reg_read(Arm64Const.UC_ARM64_REG_NZCV).intValue();
                reply.state.__pad = 0;
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
            case 4811: { // _kernelrpc_mach_vm_map
                MachVmMapRequest args = new MachVmMapRequest(request);
                args.unpack();
                log.debug("_kernelrpc_mach_vm_map args={}", args);

                MachVmMapReply reply = new MachVmMapReply(request);
                reply.unpack();

                header.setMsgBits(false);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.NDR = args.NDR;
                reply.retCode = 0;
                {
                    MachOLoader loader = (MachOLoader) emulator.getMemory();
                    UnidbgPointer pointer;
                    if (args.mask != 0) {
                        pointer = UnidbgPointer.pointer(emulator, loader.allocate(args.size, args.mask));
                    } else {
                        pointer = loader.mmap((int) args.size, args.cur_protection);
                    }
                    reply.address = UnidbgPointer.nativeValue(pointer);
                }
                reply.pack();
                log.debug("_kernelrpc_mach_vm_map reply={}, header={}", reply, header);
                return MACH_MSG_SUCCESS;
            }
            case 4817: { // mach_make_memory_entry_64
                MakeMemoryEntryRequest args = new MakeMemoryEntryRequest(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("mach_make_memory_entry_64 args={}", args);
                }
                MakeMemoryEntryReply reply = new MakeMemoryEntryReply(request);
                reply.unpack();

                header.setMsgBits(true);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                reply.status = 1;
                reply.object_handle = 0;
                reply.retCode = 0;
                reply.flags = 0x110000;
                reply.NDR = args.NDR;
                reply.outSize = args.size;
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("mach_make_memory_entry_64 reply={}, header={}", reply, header);
                }
                return MACH_MSG_SUCCESS;
            }
            case 4818: { // vm_purgable_control
                PurgableControlRequest args = new PurgableControlRequest(request);
                args.unpack();
                log.debug("vm_purgable_control args={}", args);

                PurgableControlReply reply = new PurgableControlReply(request);
                reply.unpack();

                header.setMsgBits(false);
                header.msgh_size = header.size() + reply.size();
                header.msgh_remote_port = header.msgh_local_port;
                header.msgh_local_port = 0;
                header.msgh_id += 100; // reply Id always equals reqId+100
                header.pack();

                final int VM_PURGABLE_EMPTY = 2;
                reply.NDR = args.NDR;
                reply.retCode = 0;
                reply.state = VM_PURGABLE_EMPTY;
                reply.pack();
                log.debug("vm_purgable_control reply={}, header={}", reply, header);
                return MACH_MSG_SUCCESS;
            }
            case 216: // host_statistics
                if (host_statistics(request, header)) {
                    return MACH_MSG_SUCCESS;
                }
            default:
                log.warn("mach_msg_trap header={}, size={}, lr={}", header, header.size(), UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
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

    private long audit_session_self() {
        log.debug("audit_session_self");
        return 5;
    }

    private int kevent64(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int kq = context.getIntArg(0);
        Pointer changelist = context.getPointerArg(1);
        int nchanges = context.getIntArg(2);
        Pointer eventlist = context.getPointerArg(3);
        int nevents = context.getIntArg(4);
        int flags = context.getIntArg(5);
        Pointer timeout = context.getPointerArg(6);
        return kevent64(emulator, kq, changelist, nchanges, eventlist, nevents, flags, TimeSpec.createTimeSpec(emulator, timeout));
    }

    private int sigprocmask(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int how = context.getIntArg(0);
        Pointer set = context.getPointerArg(1);
        Pointer oldset = context.getPointerArg(2);
        return sigprocmask(emulator, how, set, oldset);
    }

    private int sigaltstack(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer nstack = context.getPointerArg(0);
        Pointer ostack = context.getPointerArg(1);
        if (log.isDebugEnabled()) {
            log.debug("sigaltstack nstack={}, ostack={}", nstack, ostack);
        }
        return 0;
    }

    private long ioctl(Emulator<?> emulator) {
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

    protected long gettimeofday(Emulator<?> emulator) {
        EditableArm64RegisterContext context = emulator.getContext();
        long currentTimeMillis = System.currentTimeMillis();
        long nanoTime = System.nanoTime();
        long tv_sec = currentTimeMillis / 1000;
        long tv_usec = (currentTimeMillis % 1000) * 1000 + nanoTime % 1000;
        context.setXLong(1, tv_usec);

        Pointer tv = context.getPointerArg(0);
        if (tv != null) {
            TimeVal64 timeVal = new TimeVal64(tv);
            timeVal.tv_sec = tv_sec;
            timeVal.tv_usec = tv_usec;
            timeVal.pack();
        }

        if (log.isDebugEnabled()) {
            log.debug("gettimeofday tv_sec={}, tv_usec={}", tv_sec, tv_usec);
        }
        return tv_sec;
    }

    private long writev(Emulator<?> emulator) {
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

    private int rename(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer oldpath = context.getPointerArg(0);
        Pointer newpath = context.getPointerArg(1);
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

    private long mach_absolute_time() {
        long nanoTime = System.nanoTime();
        if (log.isDebugEnabled()) {
            log.debug("mach_absolute_time nanoTime={}", nanoTime);
        }
        return nanoTime;
    }

    private int close_NOCANCEL(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        if (log.isDebugEnabled()) {
            log.debug("close_NOCANCEL fd={}", fd);
        }

        return close(emulator, fd);
    }

    private int read_NOCANCEL(Emulator<?> emulator, int offset) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(offset);
        Pointer buffer = context.getPointerArg(offset + 1);
        int count = context.getIntArg(offset + 2);
        if (log.isDebugEnabled()) {
            log.debug("read_NOCANCEL fd={}, buffer={}, count={}, LR={}", fd, buffer, count, context.getLRPointer());
        }
        return read(emulator, fd, buffer, count);
    }

    private int getpid(Emulator<?> emulator) {
        int pid = emulator.getPid();
        log.debug("getpid pid={}", pid);
        return pid;
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

    private int connect(Emulator<?> emulator, int offset) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(offset);
        Pointer addr = context.getPointerArg(offset + 1);
        int addrlen = context.getIntArg(offset + 2);
        return connect(emulator, sockfd, addr, addrlen);
    }

    private int sigaction(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int signum = context.getIntArg(0);
        Pointer act = context.getPointerArg(1);
        Pointer oldact = context.getPointerArg(2);
        return sigaction(emulator, signum, act, oldact);
    }

    private int dup2(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int oldfd = context.getIntArg(0);
        int newfd = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("dup2 oldfd={}, newfd={}", oldfd, newfd);
        }

        FileIO old = fdMap.get(oldfd);
        if (old == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }

        if (oldfd == newfd) {
            return newfd;
        }
        DarwinFileIO _new = fdMap.remove(newfd);
        if (_new != null) {
            _new.close();
        }
        _new = (DarwinFileIO) old.dup2();
        fdMap.put(newfd, _new);
        return newfd;
    }

    private int fcntl(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int cmd = context.getIntArg(1);
        long arg = context.getLongArg(2);
        return fcntl(emulator, fd, cmd, arg);
    }

    private int fsync(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("fsync fd={}", fd);
        }
        return 0;
    }

    private long mmap(Emulator<?> emulator) {
        Arm64RegisterContext context = emulator.getContext();
        UnidbgPointer addr = context.getXPointer(0);
        int length = context.getXInt(1);
        int prot = context.getXInt(2);
        int flags = context.getXInt(3);
        int fd = context.getXInt(4);
        long offset = context.getXLong(5);

        int tag = fd >>> 24;
        if (tag != 0) {
            fd = -1;
        }

        boolean warning = length >= 0x10000000;
        long base = emulator.getMemory().mmap2(addr == null ? 0 : addr.peer, length, prot, flags, fd, (int) offset);
        String msg = "mmap addr=" + addr + ", base=0x" + Long.toHexString(base) + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset + ", tag=" + tag + ", LR=" + context.getLRPointer();
        if (log.isDebugEnabled() || warning) {
            if (warning) {
                log.warn(msg);
            } else {
                log.debug(msg);
            }
        } else if(LoggerFactory.getLogger("com.github.unidbg.ios.malloc").isDebugEnabled()) {
            log.debug(msg);
        }
        return base;
    }

    private int socket(Emulator<?> emulator, int offset) {
        RegisterContext context = emulator.getContext();
        int domain = context.getIntArg(offset);
        int type = context.getIntArg(offset + 1) & 0x7ffff;
        int protocol = context.getIntArg(offset + 2);
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

    private int write(Emulator<?> emulator, int offset) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(offset);
        Pointer buffer = context.getPointerArg(offset + 1);
        int count = context.getIntArg(offset + 2);
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
        long address = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        long length = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
        int prot = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
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
