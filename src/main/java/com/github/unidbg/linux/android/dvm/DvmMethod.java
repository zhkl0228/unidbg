package com.github.unidbg.linux.android.dvm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class DvmMethod implements Hashable {

    private static final Log log = LogFactory.getLog(DvmMethod.class);

    private final DvmClass dvmClass;
    final String methodName;
    final String args;
    final boolean isStatic;

    DvmMethod(DvmClass dvmClass, String methodName, String args, boolean isStatic) {
        this.dvmClass = dvmClass;
        this.methodName = methodName;
        this.args = args;
        this.isStatic = isStatic;
    }

    DvmObject<?>  callStaticObjectMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }

    DvmObject<?>  callStaticObjectMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    DvmObject<?>  callStaticObjectMethodA(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethodA signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticObjectMethodA(vm, dvmClass, signature, vaList);
    }

    DvmObject<?>  callObjectMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callObjectMethod signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    long callLongMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callLongMethod signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callLongMethod(vm, dvmObject, signature, varArg);
    }

    long callLongMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callLongMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callLongMethodV(vm, dvmObject, signature, vaList);
    }

    DvmObject<?>  callObjectMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callObjectMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    DvmObject<?>  callObjectMethodA(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callObjectMethodA signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callObjectMethodA(vm, dvmObject, signature, vaList);
    }

    int callIntMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callIntMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    int callBooleanMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callBooleanMethod signature=" + signature + ", dvmObject=" + dvmObject);
        }
        return dvmClass.vm.jni.callBooleanMethod(dvmClass.vm, dvmObject, signature, varArg) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callBooleanMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callBooleanMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        return dvmClass.vm.jni.callBooleanMethodV(dvmClass.vm, dvmObject, signature, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callIntMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callIntMethod signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callIntMethod(vm, dvmObject, signature, varArg);
    }

    void callVoidMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethod signature=" + signature + ", dvmObject=" + dvmObject);
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

    long callStaticLongMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticLongMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticLongMethod(vm, dvmClass, signature, varArg);
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

    void callStaticVoidMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticVoidMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callStaticVoidMethod(vm, dvmClass, signature, varArg);
    }

    void callStaticVoidMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticVoidMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }

    void callStaticVoidMethodA(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticVoidMethodA signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callStaticVoidMethodA(vm, dvmClass, signature, vaList);
    }

    DvmObject<?> newObjectV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("newObjectV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.newObjectV(vm, dvmClass, signature, vaList);
    }

    int newObject(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("newObject signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.addObject(vm.jni.newObject(vm, dvmClass, signature, varArg), false);
    }

    void callVoidMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    void callVoidMethodA(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callVoidMethodA(vm, dvmObject, signature, vaList);
    }

    float callFloatMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callFloatMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callFloatMethodV(vm, dvmObject, signature, vaList);
    }

    final DvmObject<?>  toReflectedMethod() {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("toReflectedMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.toReflectedMethod(vm, signature);
    }

    final String decodeArgsShorty() {
        StringBuilder sb = new StringBuilder();
        char[] chars = args.toCharArray();
        boolean isArray = false;
        boolean isType = false;
        for (int i = 1; i < chars.length; i++) {
            char c = chars[i];
            if (c == ')') {
                break;
            }

            if (isType) {
                if (c == ';') {
                    isType = false;
                }
                continue;
            }

            char type = '0';
            switch (c) {
                case 'L':
                    isType = true;
                    type = c;
                    break;
                case 'B':
                case 'C':
                case 'I':
                case 'S':
                case 'Z':
                case 'D':
                case 'F':
                case 'J':
                    type = c;
                    break;
                case '[':
                    isArray = true;
                    break;
                default:
                    throw new IllegalStateException("i=" + i + ", char=" + chars[i] + ", args=" + args);
            }

            if (type == '0') {
                continue;
            }

            if (isArray) {
                sb.append('L');
            } else {
                sb.append(type);
            }
            isArray = false;
        }
        return sb.toString();
    }

}
