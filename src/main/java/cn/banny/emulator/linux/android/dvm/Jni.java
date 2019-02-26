package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.Emulator;

public interface Jni {

    DvmObject getStaticObjectField(VM vm, DvmClass dvmClass, String signature);

    int getStaticIntField(DvmClass dvmClass, String signature);

    DvmObject getObjectField(VM vm, DvmObject dvmObject, String signature);

    boolean callStaticBooleanMethodV(String signature);

    int callStaticIntMethodV(String signature, VaList vaList);

    DvmObject callObjectMethodV(VM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList);

    DvmObject callStaticObjectMethod(VM vm, DvmClass dvmClass, String signature, String methodName, String args, Emulator emulator);

    DvmObject callStaticObjectMethodV(VM vm, DvmClass dvmClass, String signature, String methodName, String args, VaList vaList);

    int callIntMethodV(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList);

    long callStaticLongMethodV(String signature, VaList vaList);

    boolean callBooleanMethodV(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList);

    int getIntField(BaseVM vm, DvmObject dvmObject, String signature);

    void callStaticVoidMethodV(String signature, VaList vaList);

    void setObjectField(BaseVM vm, DvmObject dvmObject, String signature, DvmObject value);

    boolean getBooleanField(BaseVM vm, DvmObject dvmObject, String signature);

    DvmObject newObject(DvmClass clazz, String signature, Emulator emulator);

    DvmObject newObjectV(DvmClass clazz, String signature, VaList vaList);

    void setIntField(BaseVM vm, DvmObject dvmObject, String signature, int value);

    void setLongField(BaseVM vm, DvmObject dvmObject, String signature, long value);

    void setBooleanField(BaseVM vm, DvmObject dvmObject, String signature, boolean value);
}
