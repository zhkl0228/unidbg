package com.github.unidbg.linux.android.dvm;

public abstract class JniFunction implements Jni {

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticFloatMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public double callStaticDoubleMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticDoubleMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public double callStaticDoubleMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        callStaticVoidMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        callStaticVoidMethodV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticBooleanMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        return callStaticBooleanMethodV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticIntMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        return callStaticIntMethodV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticLongMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        return callStaticLongMethodV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticObjectMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        return callStaticObjectMethodV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return newObject(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        return newObjectV(vm, dvmClass, dvmMethod.getSignature(), vaList);
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
        callVoidMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        callVoidMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        return callBooleanMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callBooleanMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public char callCharMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callCharMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public char callCharMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        return callIntMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public double callDoubleMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        return callDoubleMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public double callDoubleMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public byte callByteMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callByteMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public byte callByteMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public short callShortMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callShortMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public short callShortMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callIntMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        return callObjectMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        return callLongMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callLongMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callFloatMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callObjectMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        return getStaticBooleanField(vm, dvmClass, dvmField.getSignature());
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public byte getStaticByteField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        return getStaticByteField(vm, dvmClass, dvmField.getSignature());
    }

    @Override
    public byte getStaticByteField(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        return getStaticIntField(vm, dvmClass, dvmField.getSignature());
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        return getStaticObjectField(vm, dvmClass, dvmField.getSignature());
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getBooleanField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getIntField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getLongField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public float getFloatField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getFloatField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public float getFloatField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getObjectField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, boolean value) {
        setBooleanField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature, boolean value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, int value) {
        setIntField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, String signature, int value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setFloatField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, float value) {
        setFloatField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setFloatField(BaseVM vm, DvmObject<?> dvmObject, String signature, float value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setDoubleField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, double value) {
        setDoubleField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setDoubleField(BaseVM vm, DvmObject<?> dvmObject, String signature, double value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, long value) {
        setLongField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject<?> dvmObject, String signature, long value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, DvmObject<?> value) {
        setObjectField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature, DvmObject<?> value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setStaticBooleanField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, boolean value) {
        setStaticBooleanField(vm, dvmClass, dvmField.getSignature(), value);
    }

    @Override
    public void setStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature, boolean value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, int value) {
        setStaticIntField(vm, dvmClass, dvmField.getSignature(), value);
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass dvmClass, String signature, int value) {
        throw new UnsupportedOperationException(signature);
    }

    public void setStaticObjectField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, DvmObject<?> value){
        setStaticObjectField(vm, dvmClass, dvmField.getSignature(), value);
    }

    public void setStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature, DvmObject<?> value){
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setStaticLongField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, long value) {
        setStaticLongField(vm, dvmClass, dvmField.getSignature(), value);
    }

    @Override
    public void setStaticLongField(BaseVM vm, DvmClass dvmClass, String signature, long value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setStaticFloatField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, float value) {
        setStaticFloatField(vm, dvmClass, dvmField.getSignature(), value);
    }

    @Override
    public void setStaticFloatField(BaseVM vm, DvmClass dvmClass, String signature, float value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void setStaticDoubleField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, double value) {
        setStaticDoubleField(vm, dvmClass, dvmField.getSignature(), value);
    }

    @Override
    public void setStaticDoubleField(BaseVM vm, DvmClass dvmClass, String signature, double value) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        return getStaticLongField(vm, dvmClass, dvmField.getSignature());
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public DvmObject<?> toReflectedMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod) {
        return toReflectedMethod(vm, dvmClass, dvmMethod.getSignature());
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
