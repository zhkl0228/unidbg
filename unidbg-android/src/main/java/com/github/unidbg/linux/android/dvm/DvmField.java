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
        return checkJni(vm, dvmClass).getIntField(dvmClass.vm, dvmObject, this);
    }

    long getLongField(DvmObject<?> dvmObject) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getLongField(dvmClass.vm, dvmObject, this);
    }

    float getFloatField(DvmObject<?> dvmObject) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getFloatField(dvmClass.vm, dvmObject, this);
    }

    void setObjectField(DvmObject<?> dvmObject, DvmObject<?> value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setObjectField(dvmClass.vm, dvmObject, this, value);
    }

    int getBooleanField(DvmObject<?> dvmObject) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getBooleanField(dvmClass.vm, dvmObject, this) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    void setIntField(DvmObject<?> dvmObject, int value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setIntField(dvmClass.vm, dvmObject, this, value);
    }
    
    void setLongField(DvmObject<?> dvmObject, long value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setLongField(dvmClass.vm, dvmObject, this, value);
    }

    void setBooleanField(DvmObject<?> dvmObject, boolean value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setBooleanField(dvmClass.vm, dvmObject, this, value);
    }
    
    void setDoubleField(DvmObject<?> dvmObject, double value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setDoubleField(dvmClass.vm, dvmObject, this, value);
    }

    void setStaticLongField(long value) {
        BaseVM vm = this.dvmClass.vm;
        checkJni(vm, dvmClass).setStaticLongField(this.dvmClass.vm, dvmClass, this, value);
    }

    long getStaticLongField() {
        BaseVM vm = this.dvmClass.vm;
        return checkJni(vm, dvmClass).getStaticLongField(this.dvmClass.vm, dvmClass, this);
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
