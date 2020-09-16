package com.github.unidbg.linux.android.dvm;

public interface Jni {

    void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg);

    void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList);

    boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg);

    boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList);

    int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg);

    int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList);

    long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg);

    long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList);

    DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg);

    DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList);

    DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg);

    DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList);

    DvmObject<?> allocObject(BaseVM vm, DvmClass dvmClass, String signature);

    void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg);

    void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList);

    boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg);

    boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList);

    int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg);

    int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList);

    DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg);

    long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg);

    long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList);

    float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList);

    DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList);

    int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature);

    DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature);

    boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature);

    int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature);

    long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature);

    DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature);

    void setBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature, boolean value);

    void setIntField(BaseVM vm, DvmObject<?> dvmObject, String signature, int value);

    void setDoubleField(BaseVM vm, DvmObject<?> dvmObject, String signature, double value);

    void setLongField(BaseVM vm, DvmObject<?> dvmObject, String signature, long value);

    void setObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature, DvmObject<?> value);

    void setStaticLongField(BaseVM vm, DvmClass dvmClass, String signature, long value);

    long getStaticLongField(BaseVM vm, DvmClass dvmClass, String signature);

    DvmObject<?> toReflectedMethod(BaseVM vm, DvmClass dvmClass, String signature);

    boolean acceptMethod(DvmClass dvmClass, String signature, boolean isStatic);

    boolean acceptField(DvmClass dvmClass, String signature, boolean isStatic);
}
