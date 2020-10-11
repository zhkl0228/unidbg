package com.github.unidbg.arm.backend.dynarmic;

import com.github.unidbg.arm.backend.DynarmicBackend;
import unicorn.Arm64Const;

public class DynarmicBackend64 extends DynarmicBackend {

    public DynarmicBackend64(Dynarmic dynarmic) {
        super(dynarmic);
    }

    @Override
    public Number reg_read(int regId) {
        switch (regId) {
            case Arm64Const.UC_ARM64_REG_X0:
                return dynarmic.reg_read64(0);
            case Arm64Const.UC_ARM64_REG_SP:
                return dynarmic.reg_read_sp64();
            default:
                throw new DynarmicException("regId=" + regId);
        }
    }

    @Override
    public void reg_write(int regId, Number value) {
        switch (regId) {
            case Arm64Const.UC_ARM64_REG_X30:
                dynarmic.reg_write64(30, value.longValue());
                break;
            case Arm64Const.UC_ARM64_REG_X0:
            case Arm64Const.UC_ARM64_REG_X1:
                dynarmic.reg_write64(regId - Arm64Const.UC_ARM64_REG_X0, value.longValue());
                break;
            case Arm64Const.UC_ARM64_REG_SP:
                dynarmic.reg_set_sp64(value.longValue());
                break;
            case Arm64Const.UC_ARM64_REG_TPIDR_EL0:
                dynarmic.reg_set_tpidr_el0(value.longValue());
                break;
            default:
                throw new DynarmicException("regId=" + regId);
        }
    }

}
