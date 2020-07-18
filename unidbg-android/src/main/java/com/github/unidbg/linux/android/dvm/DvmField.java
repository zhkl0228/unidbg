package com.github.unidbg.linux.android.dvm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class DvmField extends Hashable {

    private static final Log log = LogFactory.getLog(DvmField.class);

    private final DvmClass dvmClass;
    final String fieldName;
    final String fieldType;

    DvmField(DvmClass dvmClass, String fieldName, String fieldType) {
        this.dvmClass = dvmClass;
        this.fieldName = fieldName;
        this.fieldType = fieldType;
    }

    DvmObject<?> getStaticObjectField() {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getStaticObjectField dvmClass=" + dvmClass + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        return vm.jni.getStaticObjectField(vm, dvmClass, signature);
    }

    int getStaticIntField() {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getStaticIntField dvmClass=" + dvmClass + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        return dvmClass.vm.jni.getStaticIntField(vm, dvmClass, signature);
    }

    DvmObject<?> getObjectField(DvmObject<?> dvmObject) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getObjectField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        return vm.jni.getObjectField(vm, dvmObject, signature);
    }

    int getIntField(DvmObject<?> dvmObject) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getIntField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        return vm.jni.getIntField(dvmClass.vm, dvmObject, signature);
    }

    long getLongField(DvmObject<?> dvmObject) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getLongField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        return vm.jni.getLongField(dvmClass.vm, dvmObject, signature);
    }

    void setObjectField(DvmObject<?> dvmObject, DvmObject<?> value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setObjectField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        vm.jni.setObjectField(dvmClass.vm, dvmObject, signature, value);
    }

    int getBooleanField(DvmObject<?> dvmObject) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getBooleanField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        return vm.jni.getBooleanField(dvmClass.vm, dvmObject, signature) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    void setIntField(DvmObject<?> dvmObject, int value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setIntField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        vm.jni.setIntField(dvmClass.vm, dvmObject, signature, value);
    }
    
    void setLongField(DvmObject<?> dvmObject, long value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setLongField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        vm.jni.setLongField(dvmClass.vm, dvmObject, signature, value);
    }

    void setBooleanField(DvmObject<?> dvmObject, boolean value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setBooleanField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        vm.jni.setBooleanField(dvmClass.vm, dvmObject, signature, value);
    }
    
    void setDoubleField(DvmObject<?> dvmObject, double value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setDoubleField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm);
        vm.jni.setDoubleField(dvmClass.vm, dvmObject, signature, value);
    }

    void setStaticLongField(long value) {
        String signature = this.dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setStaticLongField fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        BaseVM vm = this.dvmClass.vm;
        checkJni(vm);
        vm.jni.setStaticLongField(this.dvmClass.vm, dvmClass, signature, value);
    }

    long getStaticLongField() {
        String signature = this.dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getStaticLongField fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = this.dvmClass.vm;
        checkJni(vm);
        return vm.jni.getStaticLongField(this.dvmClass.vm, dvmClass, signature);
    }

}
