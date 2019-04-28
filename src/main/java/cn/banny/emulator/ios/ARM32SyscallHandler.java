package cn.banny.emulator.ios;

import cn.banny.emulator.AbstractSyscallHandler;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.StopEmulatorException;
import cn.banny.emulator.Svc;
import cn.banny.emulator.arm.ARM;
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
public class ARM32SyscallHandler extends AbstractSyscallHandler implements SyscallHandler {

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
                    case -26: // mach_port_t mach_reply_port(...)
                        u.reg_write(ArmConst.UC_ARM_REG_R0, mach_reply_port());
                        return;
                    case -28: // mach_port_name_t task_self_trap(void)
                        u.reg_write(ArmConst.UC_ARM_REG_R0, task_self_trap());
                        return;
                    case -31:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, mach_msg_trap(emulator));
                        return;
                    case 48:
                        u.reg_write(ArmConst.UC_ARM_REG_R0, sigprocmask(u, emulator));
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

    private int mach_msg_trap(Emulator emulator) {
        throw new UnicornException();
    }

    private int task_self_trap() {
        log.debug("task_self_trap");
        return 1;
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
