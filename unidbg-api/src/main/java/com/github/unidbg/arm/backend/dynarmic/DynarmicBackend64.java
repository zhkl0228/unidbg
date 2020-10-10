package com.github.unidbg.arm.backend.dynarmic;

import com.github.unidbg.arm.backend.DynarmicBackend;
import unicorn.Arm64Const;

public class DynarmicBackend64 extends DynarmicBackend {

    public DynarmicBackend64(Dynarmic dynarmic) {
        super(dynarmic);
    }

    @Override
    public Number reg_read(int regId) {
        throw new AbstractMethodError();
    }

    @Override
    public void reg_write(int regId, Number value) {
        switch (regId) {
            case Arm64Const.UC_ARM64_REG_SP:
                dynarmic.reg_set_sp64(value.longValue());
                break;
            default:
                throw new UnsupportedOperationException("regId=" + regId);
        }
    }

}
