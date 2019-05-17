package cn.banny.unidbg.linux.android.dvm;

public interface Jni {

    DvmObject getStaticObjectField(VM vm, DvmClass dvmClass, String signature);

    int getStaticIntField(DvmClass dvmClass, String signature);

    DvmObject getObjectField(VM vm, DvmObject dvmObject, String signature);

    boolean callStaticBooleanMethod(String signature, VarArg varArg);

    boolean callStaticBooleanMethodV(String signature);

    int callStaticIntMethodV(String signature, VaList vaList);

    DvmObject callObjectMethod(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VarArg varArg);

    DvmObject callObjectMethodV(VM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList);

    DvmObject callStaticObjectMethod(VM vm, DvmClass dvmClass, String signature, String methodName, String args, VarArg varArg);

    DvmObject callStaticObjectMethodV(VM vm, DvmClass dvmClass, String signature, String methodName, String args, VaList vaList);

    int callIntMethod(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VarArg varArg);

    int callIntMethodV(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList);

    long callStaticLongMethodV(String signature, VaList vaList);

    boolean callBooleanMethodV(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList);

    int getIntField(BaseVM vm, DvmObject dvmObject, String signature);

    void callStaticVoidMethodV(String signature, VaList vaList);

    void setObjectField(BaseVM vm, DvmObject dvmObject, String signature, DvmObject value);

    boolean getBooleanField(BaseVM vm, DvmObject dvmObject, String signature);

    DvmObject newObject(DvmClass clazz, String signature, VarArg varArg);

    DvmObject newObjectV(DvmClass clazz, String signature, VaList vaList);

    void setIntField(BaseVM vm, DvmObject dvmObject, String signature, int value);

    void setLongField(BaseVM vm, DvmObject dvmObject, String signature, long value);

    void setBooleanField(BaseVM vm, DvmObject dvmObject, String signature, boolean value);

    void callVoidMethod(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VarArg varArg);

    void callVoidMethodV(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList);
}
