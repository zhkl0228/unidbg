package com.github.unidbg.arm.backend.dynarmic;

public interface DynarmicCallback {

    void callSVC(long pc, int swi);

}
