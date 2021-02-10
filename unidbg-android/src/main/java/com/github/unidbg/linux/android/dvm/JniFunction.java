package com.github.unidbg.linux.android.dvm;

public abstract class JniFunction implements Jni {

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> allocObject(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public float getFloatField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public float getFloatField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, boolean value) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature, boolean value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, int value) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, String signature, int value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setDoubleField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, double value) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public void setDoubleField(BaseVM vm, DvmObject<?> dvmObject, String signature, double value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, long value) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject<?> dvmObject, String signature, long value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, DvmObject<?> value) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature, DvmObject<?> value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, int value) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass dvmClass, String signature, int value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setStaticLongField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, long value) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public void setStaticLongField(BaseVM vm, DvmClass dvmClass, String signature, long value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        throw new UnsupportedOperationException(dvmField.getSignature());
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> toReflectedMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod) {
        throw new UnsupportedOperationException(dvmMethod.getSignature());
    }

    @Override
    public DvmObject<?> toReflectedMethod(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean acceptMethod(DvmClass dvmClass, String signature, boolean isStatic) {
        return true;
    }

    @Override
    public boolean acceptField(DvmClass dvmClass, String signature, boolean isStatic) {
        return true;
    }
}
