package com.github.unidbg.linux.android.dvm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class DvmField extends Hashable {

    private static final Log log = LogFactory.getLog(DvmField.class);

    private final DvmClass dvmClass;
    final String fieldName;
    final String fieldType;

    DvmField(DvmClass dvmClass, String fieldName, String fieldType) {
        this.dvmClass = dvmClass;
        this.fieldName = fieldName;
        this.fieldType = fieldType;
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
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getIntField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getIntField(dvmClass.vm, dvmObject, signature);
    }

    long getLongField(DvmObject<?> dvmObject) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getLongField(dvmClass.vm, dvmObject, this);
    }

    void setObjectField(DvmObject<?> dvmObject, DvmObject<?> value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setObjectField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setObjectField(dvmClass.vm, dvmObject, signature, value);
    }

    int getBooleanField(DvmObject<?> dvmObject) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getBooleanField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getBooleanField(dvmClass.vm, dvmObject, signature) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    void setIntField(DvmObject<?> dvmObject, int value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setIntField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setIntField(dvmClass.vm, dvmObject, signature, value);
    }
    
    void setLongField(DvmObject<?> dvmObject, long value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setLongField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setLongField(dvmClass.vm, dvmObject, signature, value);
    }

    void setBooleanField(DvmObject<?> dvmObject, boolean value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setBooleanField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setBooleanField(dvmClass.vm, dvmObject, signature, value);
    }
    
    void setDoubleField(DvmObject<?> dvmObject, double value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setDoubleField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setDoubleField(dvmClass.vm, dvmObject, signature, value);
    }

    void setStaticLongField(long value) {
        String signature = this.dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setStaticLongField fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = this.dvmClass.vm;
        checkJni(vm, dvmClass).setStaticLongField(this.dvmClass.vm, dvmClass, signature, value);
    }

    long getStaticLongField() {
        String signature = this.dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getStaticLongField fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = this.dvmClass.vm;
        return checkJni(vm, dvmClass).getStaticLongField(this.dvmClass.vm, dvmClass, signature);
    }

    @Override
    public String toString() {
        return getSignature();
    }
}
