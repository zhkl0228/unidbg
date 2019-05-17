package cn.banny.unidbg.linux.android.dvm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class DvmMethod implements Hashable {

    private static final Log log = LogFactory.getLog(DvmMethod.class);

    private final DvmClass dvmClass;
    private final String methodName;
    private final String args;

    DvmMethod(DvmClass dvmClass, String methodName, String args) {
        this.dvmClass = dvmClass;
        this.methodName = methodName;
        this.args = args;
    }

    DvmObject callStaticObjectMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticObjectMethod(vm, dvmClass, signature, methodName, args, varArg);
    }

    DvmObject callStaticObjectMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticObjectMethodV(vm, dvmClass, signature, methodName, args, vaList);
    }

    DvmObject callObjectMethod(DvmObject dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callObjectMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callObjectMethod(vm, dvmObject, signature, methodName, args, varArg);
    }

    DvmObject callObjectMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallObjectMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callObjectMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }

    int callIntMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callIntMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callIntMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }

    int callBooleanMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callBooleanMethodV signature=" + signature);
        }
        return dvmClass.vm.jni.callBooleanMethodV(dvmClass.vm, dvmObject, signature, methodName, args, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callIntMethod(DvmObject dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callIntMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callIntMethod(vm, dvmObject, signature, methodName, args, varArg);
    }

    void callVoidMethod(DvmObject dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callVoidMethod(vm, dvmObject, signature, methodName, args, varArg);
    }

    int callStaticIntMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticIntMethodV signature=" + signature);
        }
        return dvmClass.vm.jni.callStaticIntMethodV(signature, vaList);
    }

    long callStaticLongMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticLongMethodV signature=" + signature);
        }
        return dvmClass.vm.jni.callStaticLongMethodV(signature, vaList);
    }

    int CallStaticBooleanMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticBooleanMethod signature=" + signature);
        }
        return dvmClass.vm.jni.callStaticBooleanMethod(signature, varArg) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callStaticBooleanMethodV() {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticBooleanMethodV signature=" + signature);
        }
        return dvmClass.vm.jni.callStaticBooleanMethodV(signature) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    void callStaticVoidMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticVoidMethodV signature=" + signature);
        }
        dvmClass.vm.jni.callStaticVoidMethodV(signature, vaList);
    }

    int newObjectV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("newObjectV signature=" + signature);
        }
        return dvmClass.vm.addObject(dvmClass.vm.jni.newObjectV(dvmClass, signature, vaList), false);
    }

    int newObject(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("newObject signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.addObject(vm.jni.newObject(dvmClass, signature, varArg), false);
    }

    void callVoidMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callVoidMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }
}
