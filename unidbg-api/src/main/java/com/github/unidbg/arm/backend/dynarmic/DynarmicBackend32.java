package com.github.unidbg.arm.backend.dynarmic;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.DynarmicBackend;
import unicorn.ArmConst;

public class DynarmicBackend32 extends DynarmicBackend {

    public DynarmicBackend32(Emulator<?> emulator, Dynarmic dynarmic) {
        super(emulator, dynarmic);
    }

    @Override
    public void emu_start(long begin, long until, long timeout, long count) {
        super.emu_start(begin & 0xffffffffL, until, timeout, count);
    }

    @Override
    public void callSVC(long pc, int swi) {
        throw new AbstractMethodError();
    }

    @Override
    public boolean handleInterpreterFallback(long pc, int num_instructions) {
        throw new AbstractMethodError();
    }

    @Override
    public Number reg_read(int regId) {
        switch (regId) {
            case ArmConst.UC_ARM_REG_SP:
                return dynarmic.reg_read32(13);
            default:
                throw new DynarmicException("regId=" + regId);
        }
    }

    @Override
    public void reg_write(int regId, Number value) {
        switch (regId) {
            case ArmConst.UC_ARM_REG_SP:
                dynarmic.reg_write32(13, value.intValue());
                break;
            case ArmConst.UC_ARM_REG_LR:
                dynarmic.reg_write32(14, value.intValue());
                break;
            case ArmConst.UC_ARM_REG_C13_C0_3: // TODO
                break;
            default:
                throw new DynarmicException("regId=" + regId);
        }
    }

}
