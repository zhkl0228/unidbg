package com.github.unidbg.linux.android.dvm;

public abstract class Hashable {

    protected final void checkJni(BaseVM vm) {
        if (vm.jni == null) {
            throw new IllegalStateException("Please vm.setJni(jni)");
        }
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

}
