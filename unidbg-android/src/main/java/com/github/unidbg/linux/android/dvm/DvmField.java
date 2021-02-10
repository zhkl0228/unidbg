package com.github.unidbg.linux.android.dvm;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

public class DvmField extends Hashable {

    private final DvmClass dvmClass;
    final String fieldName;
    final String fieldType;
    private final boolean isStatic;

    DvmField(DvmClass dvmClass, String fieldName, String fieldType, boolean isStatic) {
        this.dvmClass = dvmClass;
        this.fieldName = fieldName;
        this.fieldType = fieldType;
        this.isStatic = isStatic;
    }

    public DvmClass getDvmClass() {
        return dvmClass;
    }

    public String getFieldName() {
        return fieldName;
    }

    @SuppressWarnings("unused")
    public String getFieldType() {
        return fieldType;
    }

    final String getSignature() {
        return dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
    }

    DvmObject<?> getStaticObjectField() {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getStaticObjectField(vm, dvmClass, this);
    }

    boolean getStaticBooleanField() {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getStaticBooleanField(vm, dvmClass, this);
    }

    int getStaticIntField() {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getStaticIntField(vm, dvmClass, this);
    }

    DvmObject<?> getObjectField(DvmObject<?> dvmObject) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getObjectField(vm, dvmObject, this);
    }

    int getIntField(DvmObject<?> dvmObject) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getIntField(vm, dvmObject, this);
    }

    long getLongField(DvmObject<?> dvmObject) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getLongField(vm, dvmObject, this);
    }

    float getFloatField(DvmObject<?> dvmObject) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getFloatField(vm, dvmObject, this);
    }

    void setObjectField(DvmObject<?> dvmObject, DvmObject<?> value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setObjectField(vm, dvmObject, this, value);
    }

    int getBooleanField(DvmObject<?> dvmObject) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getBooleanField(vm, dvmObject, this) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    void setIntField(DvmObject<?> dvmObject, int value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setIntField(vm, dvmObject, this, value);
    }
    
    void setLongField(DvmObject<?> dvmObject, long value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setLongField(vm, dvmObject, this, value);
    }

    void setBooleanField(DvmObject<?> dvmObject, boolean value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setBooleanField(vm, dvmObject, this, value);
    }
    
    void setDoubleField(DvmObject<?> dvmObject, double value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setDoubleField(vm, dvmObject, this, value);
    }

    void setStaticIntField(int value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setStaticIntField(vm, dvmClass, this, value);
    }

    void setStaticLongField(long value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setStaticLongField(vm, dvmClass, this, value);
    }

    long getStaticLongField() {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getStaticLongField(vm, dvmClass, this);
    }

    public Field filed;

    public void setFiled(Field filed) {
        filed.setAccessible(true);
        if (Modifier.isStatic(filed.getModifiers()) ^ isStatic) {
            throw new IllegalStateException(toString());
        }
        this.filed = filed;
    }

    @Override
    public String toString() {
        return getSignature();
    }
}
