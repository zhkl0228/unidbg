package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.StopEmulatorException;
import cn.banny.emulator.Svc;
import cn.banny.emulator.unix.UnixSyscallHandler;
import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.arm.Cpsr;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.ios.struct.*;
import cn.banny.emulator.unix.UnixEmulator;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.SyscallHandler;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;
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

        Pointer pc = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
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
                switch (NR) {
                    case -3:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, mach_absolute_time(emulator));
                        return;
                    case -15:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_vm_map_trap(emulator));
                        return;
                    case -18:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_deallocate_trap());
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
                    case 20:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, getpid(emulator));
                        return;
                    case 48:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, sigprocmask(u, emulator));
                        return;
                    case 116:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, gettimeofday(emulator));
                        return;
                    case 202:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, sysctl());
                        return;
                    case 366:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, bsdthread_register(emulator));
                        return;
                    case 372:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, thread_selfid(emulator));
                        return;
                    case 381:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, sandbox_ms());
                        return;
                    case 396:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, read_NOCANCEL(emulator));
                        return;
                    case 398:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, open_NOCANCEL(emulator));
                        return;
                    case 399:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, close_NOCANCEL(emulator));
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

        log.warn("handleInterrupt intno=" + intno + ", NR=" + NR + ", svcNumber=0x" + Integer.toHexString(svcNumber) + ", PC=" + pc + ", syscall=" + syscall, exception);

        if (exception instanceof UnicornException) {
            throw (UnicornException) exception;
        }
    }

    private int sandbox_ms() {
        // TODO: implement
        log.debug("sandbox_ms");
        return 0;
    }

    private int bsdthread_register(Emulator emulator) {
        // TODO: implement
        log.debug("bsdthread_register");
        Unicorn unicorn = emulator.getUnicorn();
        Cpsr.getArm(unicorn).setCarry(false);
        return 0;
    }

    private int semaphore_signal_trap() {
        // TODO: implement
        log.debug("semaphore_signal_trap");
        return 0;
    }

    private int sysctl() {
        // TODO: implement
        log.debug("sysctl");
        return 0;
    }

    private int _kernelrpc_mach_port_deallocate_trap() {
        // TODO: implement
        log.debug("_kernelrpc_mach_port_deallocate_trap");
        return 0;
    }

    // https://github.com/lunixbochs/usercorn/blob/master/go/kernel/mach/thread.go
    private int thread_selfid(Emulator emulator) {
        log.debug("thread_selfid");
        Unicorn unicorn = emulator.getUnicorn();
        Cpsr.getArm(unicorn).setCarry(false);
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
            default:
                log.warn("mach_msg_trap header=" + header + ", size=" + header.size());
                break;
        }

        throw new UnicornException();
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
        if (log.isDebugEnabled()) {
            log.debug("_kernelrpc_mach_vm_map_trap target=" + target + ", address=" + address + ", size=" + size + ", mask=" + mask + ", flags=0x" + Long.toHexString(flags) + ", cur_protection=" + cur_protection);
        }
        UnicornPointer pointer = emulator.getMemory().mmap((int) size, cur_protection);
        address.setPointer(0, pointer);
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

}
