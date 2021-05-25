package com.github.unidbg.linux.android.dvm;

public abstract class VaList extends VarArg {

    protected VaList(BaseVM vm, DvmMethod method) {
        super(vm, method);
    }

}
