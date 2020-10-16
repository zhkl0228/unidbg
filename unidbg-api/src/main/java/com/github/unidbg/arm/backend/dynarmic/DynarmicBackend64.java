package com.github.unidbg.arm.backend.dynarmic;

import capstone.Capstone;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.DynarmicBackend;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;

public class DynarmicBackend64 extends DynarmicBackend {

    private static final Log log = LogFactory.getLog(DynarmicBackend64.class);

    public DynarmicBackend64(Emulator<?> emulator, Dynarmic dynarmic) {
        super(emulator, dynarmic);
    }

    protected long until;

    @Override
    public void emu_start(long begin, long until, long timeout, long count) {
        this.until = until + 4;
        super.emu_start(begin, until, timeout, count);
    }

    @Override
    public boolean handleInterpreterFallback(long pc, int num_instructions) {
        if (num_instructions != 1) {
            return false;
        }
        byte[] code = mem_read(pc, 4);
        Capstone.CsInsn ins = emulator.disassemble(pc, code, false, 1)[0];
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(code, "handleInterpreterFallback pc=0x" + Long.toHexString(pc) + ", " + String.format("0x%08x: %s %s", ins.address, ins.mnemonic, ins.opStr)));
        }

        switch (ins.mnemonic) {
            case "ic": {
                // eg: ic ivau, x2
                return true;
            }
            case "nop":
            default:
                return false;
        }
    }

    @Override
    public void callSVC(long pc, int swi) {
        if (log.isDebugEnabled()) {
            log.debug("callSVC pc=0x" + Long.toHexString(pc) + ", swi=" + swi);
        }
        if (pc == until) {
            emu_stop();
            return;
        }
        interruptHookNotifier.notifyCallSVC(this);
    }

    @Override
    public Number reg_read(int regId) {
        switch (regId) {
            case Arm64Const.UC_ARM64_REG_X0:
            case Arm64Const.UC_ARM64_REG_X1:
            case Arm64Const.UC_ARM64_REG_X2:
            case Arm64Const.UC_ARM64_REG_X3:
            case Arm64Const.UC_ARM64_REG_X4:
            case Arm64Const.UC_ARM64_REG_X5:
            case Arm64Const.UC_ARM64_REG_X6:
            case Arm64Const.UC_ARM64_REG_X7:
            case Arm64Const.UC_ARM64_REG_X8:
            case Arm64Const.UC_ARM64_REG_X16:
                return dynarmic.reg_read64(regId - Arm64Const.UC_ARM64_REG_X0);
            case Arm64Const.UC_ARM64_REG_SP:
                return dynarmic.reg_read_sp64();
            case Arm64Const.UC_ARM64_REG_LR:
                return dynarmic.reg_read64(30);
            case Arm64Const.UC_ARM64_REG_PC:
                return dynarmic.reg_read_pc64();
            case Arm64Const.UC_ARM64_REG_NZCV:
                return dynarmic.reg_read_nzcv();
            default:
                throw new DynarmicException("regId=" + regId);
        }
    }

    @Override
    public void reg_write(int regId, Number value) {
        switch (regId) {
            case Arm64Const.UC_ARM64_REG_X0:
            case Arm64Const.UC_ARM64_REG_X1:
            case Arm64Const.UC_ARM64_REG_X2:
            case Arm64Const.UC_ARM64_REG_X3:
            case Arm64Const.UC_ARM64_REG_X4:
            case Arm64Const.UC_ARM64_REG_X5:
            case Arm64Const.UC_ARM64_REG_X6:
            case Arm64Const.UC_ARM64_REG_X7:
            case Arm64Const.UC_ARM64_REG_X8:
                dynarmic.reg_write64(regId - Arm64Const.UC_ARM64_REG_X0, value.longValue());
                break;
            case Arm64Const.UC_ARM64_REG_SP:
                dynarmic.reg_set_sp64(value.longValue());
                break;
            case Arm64Const.UC_ARM64_REG_LR:
                dynarmic.reg_write64(30, value.longValue());
                break;
            case Arm64Const.UC_ARM64_REG_TPIDR_EL0:
                dynarmic.reg_set_tpidr_el0(value.longValue());
                break;
            case Arm64Const.UC_ARM64_REG_TPIDRRO_EL0:
                dynarmic.reg_set_tpidrro_el0(value.longValue());
                break;
            case Arm64Const.UC_ARM64_REG_NZCV:
                dynarmic.reg_set_nzcv(value.longValue());
                break;
            default:
                throw new DynarmicException("regId=" + regId);
        }
    }

}
