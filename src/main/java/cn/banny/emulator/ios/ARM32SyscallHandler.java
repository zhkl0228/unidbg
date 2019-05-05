package cn.banny.emulator.ios;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import cn.banny.emulator.StopEmulatorException;
import cn.banny.emulator.Svc;
import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.arm.Cpsr;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.ios.file.LocalDarwinUdpSocket;
import cn.banny.emulator.ios.struct.kernel.*;
import cn.banny.emulator.memory.MemoryMap;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.SyscallHandler;
import cn.banny.emulator.unix.UnixEmulator;
import cn.banny.emulator.unix.UnixSyscallHandler;
import cn.banny.emulator.unix.file.SocketIO;
import cn.banny.emulator.unix.file.TcpSocket;
import cn.banny.emulator.unix.file.UdpSocket;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornConst;
import unicorn.UnicornException;

/**
 * http://androidxref.com/4.4.4_r1/xref/external/kernel-headers/original/asm-arm/unistd.h
 */
public class ARM32SyscallHandler extends UnixSyscallHandler implements SyscallHandler, DarwinSyscall {

    private static final Log log = LogFactory.getLog(ARM32SyscallHandler.class);

    private final SvcMemory svcMemory;

    ARM32SyscallHandler(SvcMemory svcMemory) {
        super();

        this.svcMemory = svcMemory;
    }

    @Override
    public void hook(Unicorn u, int intno, Object user) {
        Emulator emulator = (Emulator) user;

        UnicornPointer pc = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
        final int svcNumber;
        if (ARM.isThumb(u)) {
            svcNumber = pc.getShort(-2) & 0xff;
        } else {
            svcNumber = pc.getInt(-4) & 0xffffff;
        }

        int NR = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R12)).intValue();
        String syscall = null;
        Throwable exception = null;
        try {
            if (svcNumber != IOS_SYS_CALL_NUM) {
                Svc svc = svcMemory.getSvc(svcNumber);
                if (svc != null) {
                    u.reg_write(ArmConst.UC_ARM_REG_R0, svc.handle(emulator));
                    return;
                }
                u.emu_stop();
                throw new IllegalStateException("svc number: " + svcNumber);
            }

            if (log.isDebugEnabled()) {
                ARM.showThumbRegs(u);
            }

            if (intno == 2) {
                Cpsr.getArm(u).setCarry(false);
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
                    case -18:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_deallocate_trap(emulator));
                        return;
                    case -19:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_mod_refs_trap(emulator));
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
                    case 4:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, write(u, emulator));
                        return;
                    case 20:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, getpid(emulator));
                        return;
                    case 24: // getuid
                    case 25: // geteuid
                    case 43: // getegid
                    case 47: // getgid
                        u.reg_write(ArmConst.UC_ARM_REG_R0, 0);
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
                    case 92:
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
                    case 202:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, sysctl(emulator));
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
                    case 357:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, getaudit_addr(u, emulator));
                        return;
                    case 366:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, bsdthread_register(emulator));
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
                    case 398:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, open_NOCANCEL(emulator));
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
                    case 0x80000000:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, semaphore_signal_trap());
                        return;
                    default:
                        break;
                }
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

        Module module = emulator.getMemory().findModuleByAddress(pc.peer);
        log.warn("handleInterrupt intno=" + intno + ", NR=" + NR + ", svcNumber=0x" + Integer.toHexString(svcNumber) + ", PC=" + pc + ", syscall=" + syscall + (module == null ? "" : (", module=" + module + ", address=0x" + Long.toHexString(pc.peer - module.base))), exception);

        if (exception instanceof UnicornException) {
            throw (UnicornException) exception;
        }
    }

    private int stat64(Emulator emulator) {
        Pointer pathname = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer statbuf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        String path = FilenameUtils.normalize(pathname.getString(0));
        if (log.isDebugEnabled()) {
            log.debug("stat64 pathname=" + path + ", statbuf=" + statbuf);
        }
        return stat64(emulator, path, statbuf);
    }

    private int write_NOCANCEL(Emulator emulator) {
        Unicorn u = emulator.getUnicorn();
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        return write(emulator, fd, buffer, count);
    }

    private int fstat(Unicorn u, Emulator emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer stat = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        return fstat(emulator, fd, stat);
    }

    private static final int RLIMIT_NOFILE = 8;		/* number of open files */
    private static final int RLIMIT_POSIX_FLAG = 0x1000;	/* Set bit for strict POSIX */

    private int getrlimit(Unicorn u, Emulator emulator) {
        int resource = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer rlp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        boolean posix = (resource & RLIMIT_POSIX_FLAG) != 0;
        int type = resource & (RLIMIT_POSIX_FLAG - 1);
        if (type == RLIMIT_NOFILE) {
            if (log.isDebugEnabled()) {
                log.info("getrlimit resource=0x" + Integer.toHexString(resource) + ", rlp=" + rlp + ", posix=" + posix + ", type=" + type);
            }
            RLimit rLimit = new RLimit(rlp);
            rLimit.rlim_cur = 128;
            rLimit.rlim_max = 256;
            rLimit.pack();
            return 0;
        } else {
            log.info("getrlimit resource=0x" + Integer.toHexString(resource) + ", rlp=" + rlp + ", posix=" + posix + ", type=" + type);
        }
        return 1;
    }

    private int _kernelrpc_mach_port_mod_refs_trap(Emulator emulator) {
        // TODO: implement
        Unicorn unicorn = emulator.getUnicorn();
        int task = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int name = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int right = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int delta = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        log.info("_kernelrpc_mach_port_mod_refs_trap task=" + task + ", name=" + name + ", right=" + right + ", delta=" + delta);
        return 0;
    }

    private int _kernelrpc_mach_port_construct_trap(Emulator emulator) {
        // TODO: implement
        Unicorn unicorn = emulator.getUnicorn();
        int task = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer options = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int r2 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        long r3 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        long context = r2 | (r3 << 32);
        Pointer name = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        log.info("_kernelrpc_mach_port_construct_trap task=" + task + ", options=" + options + ", context=0x" + Long.toHexString(context) + ", name=" + name);
        return 0;
    }

    private int getaudit_addr(Unicorn u, Emulator emulator) {
        Pointer addr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int size = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("getaudit_addr=" + addr + ", size=" + size);
        }
        return 0;
    }

    private static final int PROC_INFO_CALL_SETCONTROL = 0x5;
    private static final int PROC_SELFSET_THREADNAME = 2;

    private int proc_info(Emulator emulator) {
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
            log.debug(msg);
            ((Dyld) emulator.getDlfcn()).pthread_setname_np(threadName);
            return 0;
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

    private int pthread_sigmask(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int how = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer set = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oset = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        if (log.isDebugEnabled()) {
            log.debug("pthread_sigmask how=" + how + ", set=" + set + ", oset=" + oset);
        }
        return 0;
    }

    private int sandbox_ms(Emulator emulator) {
        // TODO: implement
        Unicorn unicorn = emulator.getUnicorn();
        Pointer policyName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int call = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        Pointer args = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        log.info("sandbox_ms policyName=" + policyName.getString(0) + ", call=" + call + ", args=" + args);
        return 0;
    }

    private int issetugid() {
        log.debug("issetugid");
        return 0;
    }

    private int bsdthread_register(Emulator emulator) {
        // TODO: implement
        log.info("bsdthread_register");
        return 0;
    }

    private int semaphore_signal_trap() {
        // TODO: implement
        log.info("semaphore_signal_trap");
        return 0;
    }

    private int munmap(Unicorn u, Emulator emulator) {
        long timeInMillis = System.currentTimeMillis();
        long start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue() & 0xffffffffL;
        int length = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int ret = emulator.getMemory().munmap(start, length);
        if (log.isDebugEnabled()) {
            log.debug("munmap start=0x" + Long.toHexString(start) + ", length=" + length + ", ret=" + ret + ", offset=" + (System.currentTimeMillis() - timeInMillis));
        }
        return ret;
    }

    private static final int CTL_UNSPEC = 0;
    private static final int CTL_KERN = 1;
    private static final int CTL_HW = 6;

    private static final int KERN_OSRELEASE = 2;
    private static final int KERN_OSVERSION = 65;

    private static final int HW_PAGESIZE = 7;

    private static final int KERN_USRSTACK32 = 35;

    private int sysctl(Emulator emulator) {
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
                    case KERN_USRSTACK32:
                        log.debug(msg);
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

    private int _kernelrpc_mach_vm_deallocate_trap(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int target = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        long r1 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        long r2 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        long address = r1 | (r2 << 32);
        long r3 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        long r4 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        long size = r3 | (r4 << 32);

        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_deallocate_trap target=" + target + ", address=0x" + Long.toHexString(address) + ", size=" + size);
        }
        emulator.getMemory().munmap(address, (int) size);
        return 0;
    }

    private static final int VM_FLAGS_ANYWHERE = 0x0001;
    private static final int VM_MEMORY_MALLOC = 0x1000000;

    private int _kernelrpc_mach_vm_allocate_trap(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        int target = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer address = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        long r2 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        long r3 = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        long size = r2 | (r3 << 32);
        int flags = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        boolean anywhere = (flags & VM_FLAGS_ANYWHERE) != 0;
        boolean malloc = (flags & VM_MEMORY_MALLOC) != 0;

        Pointer value = address.getPointer(0);
        UnicornPointer pointer = emulator.getMemory().mmap((int) size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);
        address.setPointer(0, pointer);
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_allocate_trap target=" + target + ", address=" + address + ", value=" + value + ", size=0x" + Long.toHexString(size) + ", flags=0x" + Integer.toHexString(flags) + ", pointer=" + pointer + ", anywhere=" + anywhere + ", malloc=" + malloc);
        }
        return 0;
    }

    private int _kernelrpc_mach_port_deallocate_trap(Emulator emulator) {
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
    private int mach_msg_trap(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        UnicornPointer msg = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int option = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int send_size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int rcv_size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        int rcv_name = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        int timeout = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R5)).intValue();
        int notify = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R6)).intValue();

        msg.setSize(rcv_size);

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

                switch (args.which) {
                    case TASK_BOOTSTRAP_PORT:
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

                switch (args.flavor) {
                    case HOST_PRIORITY_INFO:
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
                VmRegionRecurse64Request args = new VmRegionRecurse64Request(request);
                args.unpack();
                if (log.isDebugEnabled()) {
                    log.debug("vm_region_recurse_64 args=" + args);
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
                    if (args.address >= mm.base && args.address < mm.base + mm.size) {
                        memoryMap = mm;
                        break;
                    }
                }

                if (memoryMap == null) {
                    break;
                }

                reply.NDR = args.NDR;
                reply.retCode = 0; // success
                reply.address = (int) memoryMap.base;
                reply.size = memoryMap.size;
                reply.infoCnt = args.infoCnt;
                reply.nestingDepth = args.nestingDepth;
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
                    log.debug("task_get_exception_ports args=" + args);
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
                reply.pack();

                if (log.isDebugEnabled()) {
                    log.debug("task_get_exception_ports reply=" + reply);
                }
                return MACH_MSG_SUCCESS;
            }
            default:
                log.warn("mach_msg_trap header=" + header + ", size=" + header.size());
                break;
        }

        return -1;
    }

    private int _kernelrpc_mach_vm_map_trap(Emulator emulator) {
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
        UnicornPointer pointer = emulator.getMemory().mmap((int) size, cur_protection);
        address.setPointer(0, pointer);
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_map_trap target=" + target + ", address=" + address + ", size=0x" + Long.toHexString(size) + ", mask=0x" + Long.toHexString(mask) + ", flags=0x" + Long.toHexString(flags) + ", cur_protection=" + cur_protection + ", pointer=" + pointer);
        }
        return 0;
    }

    private static final int BOOTSTRAP_PORT = 11;
    private static final int CLOCK_SERVER_PORT = 13;
    private static final int SEMAPHORE_PORT = 14;

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

    private int sigprocmask(Unicorn u, Emulator emulator) {
        int how = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer set = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oldset = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
        return sigprocmask(emulator, how, set, oldset);
    }

    private int gettimeofday(Emulator emulator) {
        Pointer tv = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        Pointer tz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        return gettimeofday(tv, tz);
    }

    private int mach_absolute_time(Emulator emulator) {
        long nanoTime = System.nanoTime();
        log.debug("mach_absolute_time nanoTime=" + nanoTime);
        emulator.getUnicorn().reg_write(ArmConst.UC_ARM_REG_R1, (int) (nanoTime >> 32));
        return (int) (nanoTime);
    }

    private int close_NOCANCEL(Emulator emulator) {
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

    private int read_NOCANCEL(Emulator emulator) {
        Unicorn u = emulator.getUnicorn();
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("read_NOCANCEL fd=" + fd + ", buffer=" + buffer + ", count=" + count);
        }
        return read(emulator, fd, buffer, count);
    }

    private int open_NOCANCEL(Emulator emulator) {
        Unicorn u = emulator.getUnicorn();
        Pointer pathname_p = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int oflags = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int mode = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        String pathname = pathname_p.getString(0);
        int fd = open(emulator, pathname, oflags);
        if (fd == -1) {
            log.info("open_NOCANCEL pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode));
        } else if (log.isDebugEnabled()) {
            log.debug("open_NOCANCEL pathname=" + pathname + ", oflags=0x" + Integer.toHexString(oflags) + ", mode=" + Integer.toHexString(mode) + ", fd=" + fd);
        }
        return fd;
    }

    private int getpid(Emulator emulator) {
        int pid = emulator.getPid();
        log.debug("getpid pid=" + pid);
        return pid;
    }

    private int sendto(Unicorn u, Emulator emulator) {
        int sockfd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int len = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int flags = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        Pointer dest_addr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R4);
        int addrlen = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R5)).intValue();

        return sendto(emulator, sockfd, buf, len, flags, dest_addr, addrlen);
    }

    private int connect(Unicorn u, Emulator emulator) {
        int sockfd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer addr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int addrlen = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        return connect(emulator, sockfd, addr, addrlen);
    }

    private int sigaction(Unicorn u, Emulator emulator) {
        int signum = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer act = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        Pointer oldact = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);

        return sigaction(signum, act, oldact);
    }

    private int fcntl(Unicorn u, Emulator emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        int cmd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int arg = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        return fcntl(emulator, fd, cmd, arg);
    }

    private static final int MMAP2_SHIFT = 12;

    private int mmap(Unicorn u, Emulator emulator) {
        UnicornPointer addr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int length = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int prot = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int flags = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        int offset = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R5)).intValue() << MMAP2_SHIFT;

        int tag = fd >>> 24;
        if (tag != 0) {
            fd = -1;
        }

        boolean warning = length >= 0x10000000;
        if (log.isDebugEnabled() || warning) {
            String msg = "mmap addr=" + addr + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset + ", tag=" + tag;
            if (warning) {
                log.warn(msg);
            } else {
                log.debug(msg);
            }
        }
        return emulator.getMemory().mmap2(addr == null ? 0 : addr.peer, length, prot, flags, fd, offset);
    }

    private int socket(Unicorn u, Emulator emulator) {
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
                switch (type) {
                    case SocketIO.SOCK_DGRAM:
                        fd = getMinFd();
                        fdMap.put(fd, new LocalDarwinUdpSocket(emulator));
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

    private int write(Unicorn u, Emulator emulator) {
        int fd = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        Pointer buffer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
        int count = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        byte[] data = buffer.getByteArray(0, count);
        if (log.isDebugEnabled()) {
            Inspector.inspect(data, "write fd=" + fd + ", buffer=" + buffer + ", count=" + count);
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.write(data);
    }

    private int mprotect(Unicorn u, Emulator emulator) {
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

}
