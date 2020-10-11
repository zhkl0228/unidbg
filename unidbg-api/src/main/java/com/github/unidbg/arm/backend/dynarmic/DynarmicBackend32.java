package com.github.unidbg.arm.backend.dynarmic;

import com.github.unidbg.arm.backend.DynarmicBackend;

public class DynarmicBackend32 extends DynarmicBackend {

    public DynarmicBackend32(Dynarmic dynarmic) {
        super(dynarmic);
    }

    @Override
    public void callSVC(long pc, int swi) {
        throw new AbstractMethodError();
    }

    @Override
    public Number reg_read(int regId) {
        throw new AbstractMethodError();
    }

    @Override
    public void reg_write(int regId, Number value) {
        throw new AbstractMethodError();
    }

}
