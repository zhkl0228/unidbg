package com.github.unidbg.linux.android.dvm;

public abstract class Hashable {

    protected final Jni checkJni(BaseVM vm, DvmClass dvmClass) {
        Jni classJni = dvmClass.getJni();
        if (vm.jni == null && classJni == null) {
            throw new IllegalStateException("Please vm.setJni(jni)");
        }
        return classJni != null ? classJni : vm.jni;
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

}
