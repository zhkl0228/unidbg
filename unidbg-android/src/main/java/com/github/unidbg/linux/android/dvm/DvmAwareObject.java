package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;

public interface DvmAwareObject {

    void initializeDvm(Emulator<?> emulator, VM vm, DvmObject<?> object);

}
