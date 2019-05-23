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
        return vm.jni.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }

    DvmObject callStaticObjectMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    DvmObject callObjectMethod(DvmObject dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callObjectMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    DvmObject callObjectMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallObjectMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    int callIntMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callIntMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    int callBooleanMethod(DvmObject dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callBooleanMethod signature=" + signature);
        }
        return dvmClass.vm.jni.callBooleanMethod(dvmClass.vm, dvmObject, signature, varArg) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callBooleanMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callBooleanMethodV signature=" + signature);
        }
        return dvmClass.vm.jni.callBooleanMethodV(dvmClass.vm, dvmObject, signature, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callIntMethod(DvmObject dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callIntMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callIntMethod(vm, dvmObject, signature, varArg);
    }

    void callVoidMethod(DvmObject dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callVoidMethod(vm, dvmObject, signature, varArg);
    }

    int callStaticIntMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticIntMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticIntMethod(vm, dvmClass, signature, varArg);
    }

    int callStaticIntMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticIntMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticIntMethodV(vm, dvmClass, signature, vaList);
    }

    long callStaticLongMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticLongMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticLongMethodV(vm, dvmClass, signature, vaList);
    }

    int CallStaticBooleanMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticBooleanMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticBooleanMethod(vm, dvmClass, signature, varArg) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callStaticBooleanMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticBooleanMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticBooleanMethodV(vm, dvmClass, signature, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    void callStaticVoidMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticVoidMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }

    int newObjectV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("newObjectV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.addObject(vm.jni.newObjectV(vm, dvmClass, signature, vaList), false);
    }

    int newObject(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("newObject signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.addObject(vm.jni.newObject(vm, dvmClass, signature, varArg), false);
    }

    void callVoidMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callVoidMethodV(vm, dvmObject, signature, vaList);
    }
}
