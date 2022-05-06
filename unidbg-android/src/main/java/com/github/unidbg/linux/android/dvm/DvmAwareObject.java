package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.AndroidEmulator;

public interface DvmAwareObject {

    void initializeDvm(AndroidEmulator emulator, VM vm, DvmObject<?> object);

}
