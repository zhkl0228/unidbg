package cn.banny.emulator.ios;

import cn.banny.emulator.AbstractSyscallHandler;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.StopEmulatorException;
import cn.banny.emulator.Svc;
import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.arm.Cpsr;
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

    private int bsdthread_register(Emulator emulator) {
        // TODO: implement
        Unicorn unicorn = emulator.getUnicorn();
        Cpsr.getArm(unicorn).setCarry(false);
        return 0;
    }

    private int semaphore_signal_trap(Emulator emulator) {
        // TODO: implement
        return 0;
    }

    private int thread_selfid(Emulator emulator) {
        // TODO: implement
        Unicorn unicorn = emulator.getUnicorn();
        Cpsr.getArm(unicorn).setCarry(false);
        return 0;
    }

    private int sysctl(Emulator emulator) {
        // TODO: implement
        return 0;
    }

    private int _kernelrpc_mach_port_deallocate_trap(Emulator emulator) {
        // TODO: implement
        return 0;
    }

    private int mach_msg_trap(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        Pointer msg = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
        int option = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
        int send_size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
        int rcv_size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
        int rcv_name = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R4)).intValue();
        int timeout = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R5)).intValue();
        int notify = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R6)).intValue();
        if (log.isDebugEnabled()) {
            log.debug("mach_msg_trap msg=" + msg + ", option=0x" + Integer.toHexString(option) + ", send_size=" + send_size + ", rcv_size=" + rcv_size + ", rcv_name=" + rcv_name + ", timeout=" + timeout + ", notify=" + notify);
        }

        int msgh_bits = msg.getInt(0);
        int msgh_size = msg.getInt(4);
        int msgh_remote_port = msg.getInt(8);
        int msgh_local_port = msg.getInt(0xc);
        int msgh_voucher_port = msg.getInt(0x10);
        int msgh_id = msg.getInt(0x14);
        final Pointer request = msg.share(0x18);

        switch (msgh_id) {
            case 3409: // task_get_special_port
                int mig_vers = request.getByte(0) & 0xff;
                int if_vers = request.getByte(1) & 0xff;
                int reserved1 = request.getByte(2) & 0xff;
                int mig_encoding = request.getByte(3) & 0xff;
                int int_rep = request.getByte(4) & 0xff;
                int char_rep = request.getByte(5) & 0xff;
                int float_rep = request.getByte(6) & 0xff;
                int reserved2 = request.getByte(7) & 0xff;
                int which = request.getInt(8);
                log.debug("task_get_special_port mig_vers=" + mig_vers + ", if_vers=" + if_vers + ", reserved1=" + reserved1 + ", mig_encoding=" + mig_encoding + ", int_rep=" + int_rep + ", char_rep=" + char_rep + ", float_rep=" + float_rep + ", reserved2=" + reserved2 + ", which=" + which);

                switch (which) {
                    case TASK_BOOTSTRAP_PORT:
                        msg.setInt(0, (msgh_bits & 0xff) | MACH_MSGH_BITS_COMPLEX);
                        msg.setInt(4, 40);
                        msg.setInt(8, msgh_local_port);
                        msg.setInt(0xc, 0);
                        msg.setInt(0x14, msgh_id + 100); // reply Id always equals reqId+100

                        Pointer msgBody = msg.share(0x18);
                        msgBody.setInt(0, 1); // msgh_descriptor_count

                        Pointer reply = msgBody.share(4); // mach_msg_port_descriptor_t
                        reply.setInt(0, BOOTSTRAP_PORT); // I just chose 11 randomly here
                        reply.setInt(4, 0); // pad1
                        reply.setShort(8, (short) 0); // pad2
                        reply.setByte(10, (byte) 17); // disposition meaning?
                        reply.setByte(11, (byte) MACH_MSG_PORT_DESCRIPTOR);
                        return MACH_MSG_SUCCESS;
                }
            case 200: // host_info
                int flavor = request.getInt(8);
                int host_info_out = request.getInt(0xc);
                log.debug("host_info flavor=" + flavor + ", host_info_out=" + host_info_out);

                switch (flavor) {
                    case HOST_PRIORITY_INFO:
                        msg.setInt(0, msgh_bits & 0xff);
                        msg.setInt(4, 72);
                        msg.setInt(8, msgh_local_port);
                        msg.setInt(0xc, 0);
                        msg.setInt(0x14, msgh_id + 100); // reply Id always equals reqId+100

                        Pointer msgBody = msg.share(0x18);
                        msgBody.write(0, request.getByteArray(0, 8), 0, 8); // NDR
                        msgBody.setInt(8, 0); // RetCode success
                        msgBody.setInt(0xc, host_info_out); // host_info_outCnt

                        msgBody.setInt(0x10, 0); // kernel_priority
                        msgBody.setInt(0x14, 0); // system_priority
                        msgBody.setInt(0x18, 0); // server_priority
                        msgBody.setInt(0x1c, 0); // user_priority
                        msgBody.setInt(0x20, 0); // depress_priority
                        msgBody.setInt(0x24, 10); // idle_priority
                        msgBody.setInt(0x28, 10); // minimum_priority
                        msgBody.setInt(0x2c, -10); // maximum_priority
                        return MACH_MSG_SUCCESS;
                }
            default:
                log.warn("mach_msg_trap_header msgh_bits=" + msgh_bits + ", msgh_size=" + msgh_size + ", msgh_remote_port=" + msgh_remote_port + ", msgh_local_port=" + msgh_local_port + ", msgh_voucher_port=" + msgh_voucher_port + ", msgh_id=" + msgh_id);
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
        return 2;
    }

    private int thread_self_trap() {
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
