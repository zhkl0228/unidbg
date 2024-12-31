package com.github.unidbg.linux.android.dvm;

public abstract class JniFunction implements Jni {

    private final Jni fallbackJni;

    protected JniFunction(Jni fallbackJni) {
        this.fallbackJni = fallbackJni;
    }

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticFloatMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callStaticFloatMethod(vm, dvmClass, signature, varArg);
        }
    }

    @Override
    public double callStaticDoubleMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticDoubleMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public double callStaticDoubleMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callStaticDoubleMethod(vm, dvmClass, signature, varArg);
        }
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        callStaticVoidMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.callStaticVoidMethod(vm, dvmClass, signature, varArg);
        }
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        callStaticVoidMethodV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticBooleanMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callStaticBooleanMethod(vm, dvmClass, signature, varArg);
        }
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        return callStaticBooleanMethodV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callStaticBooleanMethodV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticIntMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callStaticIntMethod(vm, dvmClass, signature, varArg);
        }
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        return callStaticIntMethodV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callStaticIntMethodV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticLongMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callStaticLongMethod(vm, dvmClass, signature, varArg);
        }
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        return callStaticLongMethodV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callStaticLongMethodV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return callStaticObjectMethod(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callStaticObjectMethod(vm, dvmClass, signature, varArg);
        }
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        return callStaticObjectMethodV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        return newObject(vm, dvmClass, dvmMethod.getSignature(), varArg);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.newObject(vm, dvmClass, signature, varArg);
        }
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        return newObjectV(vm, dvmClass, dvmMethod.getSignature(), vaList);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.newObjectV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public DvmObject<?> allocObject(BaseVM vm, DvmClass dvmClass, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.allocObject(vm, dvmClass, signature);
        }
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        callVoidMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.callVoidMethod(vm, dvmObject, signature, varArg);
        }
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        callVoidMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.callVoidMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        return callBooleanMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callBooleanMethod(vm, dvmObject, signature, varArg);
        }
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callBooleanMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callBooleanMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public char callCharMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callCharMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public char callCharMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callCharMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        return callIntMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callIntMethod(vm, dvmObject, signature, varArg);
        }
    }

    @Override
    public double callDoubleMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        return callDoubleMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public double callDoubleMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callDoubleMethod(vm, dvmObject, signature, varArg);
        }
    }

    @Override
    public byte callByteMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callByteMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public byte callByteMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callByteMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public short callShortMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callShortMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public short callShortMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callShortMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callIntMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callIntMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        return callObjectMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callObjectMethod(vm, dvmObject, signature, varArg);
        }
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        return callLongMethod(vm, dvmObject, dvmMethod.getSignature(), varArg);
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callLongMethod(vm, dvmObject, signature, varArg);
        }
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callLongMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callLongMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callFloatMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callFloatMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        return callObjectMethodV(vm, dvmObject, dvmMethod.getSignature(), vaList);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.callObjectMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        return getStaticBooleanField(vm, dvmClass, dvmField.getSignature());
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getStaticBooleanField(vm, dvmClass, signature);
        }
    }

    @Override
    public byte getStaticByteField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        return getStaticByteField(vm, dvmClass, dvmField.getSignature());
    }

    @Override
    public byte getStaticByteField(BaseVM vm, DvmClass dvmClass, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getStaticByteField(vm, dvmClass, signature);
        }
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        return getStaticIntField(vm, dvmClass, dvmField.getSignature());
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getStaticIntField(vm, dvmClass, signature);
        }
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        return getStaticObjectField(vm, dvmClass, dvmField.getSignature());
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getStaticObjectField(vm, dvmClass, signature);
        }
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getBooleanField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getBooleanField(vm, dvmObject, signature);
        }
    }

    @Override
    public byte getByteField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getByteField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public byte getByteField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getByteField(vm, dvmObject, signature);
        }
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getIntField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getIntField(vm, dvmObject, signature);
        }
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getLongField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getLongField(vm, dvmObject, signature);
        }
    }

    @Override
    public float getFloatField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getFloatField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public float getFloatField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getFloatField(vm, dvmObject, signature);
        }
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        return getObjectField(vm, dvmObject, dvmField.getSignature());
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getObjectField(vm, dvmObject, signature);
        }
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, boolean value) {
        setBooleanField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature, boolean value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setBooleanField(vm, dvmObject, signature, value);
        }
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, int value) {
        setIntField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, String signature, int value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setIntField(vm, dvmObject, signature, value);
        }
    }

    @Override
    public void setFloatField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, float value) {
        setFloatField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setFloatField(BaseVM vm, DvmObject<?> dvmObject, String signature, float value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setFloatField(vm, dvmObject, signature, value);
        }
    }

    @Override
    public void setDoubleField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, double value) {
        setDoubleField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setDoubleField(BaseVM vm, DvmObject<?> dvmObject, String signature, double value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setDoubleField(vm, dvmObject, signature, value);
        }
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, long value) {
        setLongField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject<?> dvmObject, String signature, long value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setLongField(vm, dvmObject, signature, value);
        }
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, DvmObject<?> value) {
        setObjectField(vm, dvmObject, dvmField.getSignature(), value);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature, DvmObject<?> value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setObjectField(vm, dvmObject, signature, value);
        }
    }

    @Override
    public void setStaticBooleanField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, boolean value) {
        setStaticBooleanField(vm, dvmClass, dvmField.getSignature(), value);
    }

    @Override
    public void setStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature, boolean value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setStaticBooleanField(vm, dvmClass, signature, value);
        }
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, int value) {
        setStaticIntField(vm, dvmClass, dvmField.getSignature(), value);
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass dvmClass, String signature, int value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setStaticIntField(vm, dvmClass, signature, value);
        }
    }

    public void setStaticObjectField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, DvmObject<?> value){
        setStaticObjectField(vm, dvmClass, dvmField.getSignature(), value);
    }

    public void setStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature, DvmObject<?> value){
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setStaticObjectField(vm, dvmClass, signature, value);
        }
    }

    @Override
    public void setStaticLongField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, long value) {
        setStaticLongField(vm, dvmClass, dvmField.getSignature(), value);
    }

    @Override
    public void setStaticLongField(BaseVM vm, DvmClass dvmClass, String signature, long value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setStaticLongField(vm, dvmClass, signature, value);
        }
    }

    @Override
    public void setStaticFloatField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, float value) {
        setStaticFloatField(vm, dvmClass, dvmField.getSignature(), value);
    }

    @Override
    public void setStaticFloatField(BaseVM vm, DvmClass dvmClass, String signature, float value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setStaticFloatField(vm, dvmClass, signature, value);
        }
    }

    @Override
    public void setStaticDoubleField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, double value) {
        setStaticDoubleField(vm, dvmClass, dvmField.getSignature(), value);
    }

    @Override
    public void setStaticDoubleField(BaseVM vm, DvmClass dvmClass, String signature, double value) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            fallbackJni.setStaticDoubleField(vm, dvmClass, signature, value);
        }
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        return getStaticLongField(vm, dvmClass, dvmField.getSignature());
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.getStaticLongField(vm, dvmClass, signature);
        }
    }

    @Override
    public DvmObject<?> toReflectedMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod) {
        return toReflectedMethod(vm, dvmClass, dvmMethod.getSignature());
    }

    @Override
    public DvmObject<?> toReflectedMethod(BaseVM vm, DvmClass dvmClass, String signature) {
        if (fallbackJni == null) {
            throw new UnsupportedOperationException(signature);
        } else {
            return fallbackJni.toReflectedMethod(vm, dvmClass, signature);
        }
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
