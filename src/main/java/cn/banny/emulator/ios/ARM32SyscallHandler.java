package cn.banny.emulator.ios;

import cn.banny.emulator.AbstractSyscallHandler;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.StopEmulatorException;
import cn.banny.emulator.Svc;
import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.arm.Cpsr;
import cn.banny.emulator.ios.struct.*;
import cn.banny.emulator.linux.LinuxEmulator;
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
public class ARM32SyscallHandler extends AbstractSyscallHandler implements SyscallHandler, DarwinSyscall {

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
                    case -15:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_vm_map_trap(emulator));
                        return;
                    case -18:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, _kernelrpc_mach_port_deallocate_trap(emulator));
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
                    case 48:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, sigprocmask(u, emulator));
                        return;
                    case 202:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, sysctl(emulator));
                        return;
                    case 366:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, bsdthread_register(emulator));
                        return;
                    case 372:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, thread_selfid(emulator));
                        return;
                    case 0x80000000:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, semaphore_signal_trap(emulator));
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

    private int _kernelrpc_mach_vm_map_trap(Emulator emulator) {
        // TODO: implement
        Unicorn unicorn = emulator.getUnicorn();
        int target = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
        long address = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue() & 0xffffffffL;
        int size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int mask = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        int flags = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        int cur_protection = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R5)).intValue();
        log.debug("_kernelrpc_mach_vm_map_trap target=" + target + ", address=0x" + Long.toHexString(address) + ", size=" + size + ", mask=" + mask + ", flags=" + flags + ", cur_protection=" + cur_protection);
        return 0;
    }

    private int bsdthread_register(Emulator emulator) {
        // TODO: implement
        log.debug("bsdthread_register");
        Unicorn unicorn = emulator.getUnicorn();
        Cpsr.getArm(unicorn).setCarry(false);
        return 0;
    }

    private int semaphore_signal_trap(Emulator emulator) {
        // TODO: implement
        log.debug("semaphore_signal_trap");
        return 0;
    }

    private int thread_selfid(Emulator emulator) {
        // TODO: implement
        log.debug("thread_selfid");
        Unicorn unicorn = emulator.getUnicorn();
        Cpsr.getArm(unicorn).setCarry(false);
        return 0;
    }

    private int sysctl(Emulator emulator) {
        // TODO: implement
        log.debug("sysctl");
        return 0;
    }

    private int _kernelrpc_mach_port_deallocate_trap(Emulator emulator) {
        // TODO: implement
        log.debug("_kernelrpc_mach_port_deallocate_trap");
        return 0;
    }

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

        final Pointer request = msg.share(0x18);

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
                        Pointer msgBody = msg.share(0x18);
                        TaskGetSpecialPortReply reply = new TaskGetSpecialPortReply(msgBody);
                        reply.unpack();

                        header.msgh_bits = (header.msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX;
                        header.msgh_size = header.size() + reply.size();
                        header.msgh_remote_port = header.msgh_local_port;
                        header.msgh_local_port = 0;
                        header.msgh_id += 100; // reply Id always equals reqId+100
                        header.pack();

                        reply.body.msgh_descriptor_count = 1;
                        reply.specialPort.name = BOOTSTRAP_PORT; // I just chose 11 randomly here
                        reply.specialPort.pad1 = 0;
                        reply.specialPort.pad2 = 0;
                        reply.specialPort.disposition = 17; // meaning?
                        reply.specialPort.type = MACH_MSG_PORT_DESCRIPTOR;
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
                        Pointer msgBody = msg.share(0x18);
                        HostInfoReply reply = new HostInfoReply(msgBody);
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
            default:
                log.warn("mach_msg_trap header=" + header + ", size=" + header.size());
                break;
        }

        throw new UnicornException();
    }

    private static final int BOOTSTRAP_PORT = 11;

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
        if (log.isDebugEnabled()) {
            log.debug("sigprocmask how=" + how + ", set=" + set + ", oldset=" + oldset);
        }
        emulator.getMemory().setErrno(LinuxEmulator.EINVAL);
        return -1;
    }

    @Override
    public int open(Emulator emulator, String pathname, int oflags) {
        log.info("open pathname=" + pathname);
        return 0;
    }
}
