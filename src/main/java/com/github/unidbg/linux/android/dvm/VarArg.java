package com.github.unidbg.linux.android.dvm;

public interface VarArg {

    /**
     * @param index 0 based
     */
    <T extends DvmObject<?>> T getObject(int index);

    /**
     * @param index 0 based
     */
    int getInt(int index);

}
