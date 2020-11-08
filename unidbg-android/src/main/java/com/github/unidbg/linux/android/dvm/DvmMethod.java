package com.github.unidbg.linux.android.dvm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class DvmMethod extends Hashable {

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

    public DvmClass getDvmClass() {
        return dvmClass;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getArgs() {
        return args;
    }

    final String getSignature() {
        return dvmClass.getClassName() + "->" + methodName + args;
    }

    DvmObject<?>  callStaticObjectMethod(VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticObjectMethod(vm, dvmClass, this, varArg);
    }

    DvmObject<?>  callStaticObjectMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    DvmObject<?>  callStaticObjectMethodA(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethodA signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    DvmObject<?>  callObjectMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callObjectMethod(vm, dvmObject, this, varArg);
    }

    long callLongMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callLongMethod signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callLongMethod(vm, dvmObject, signature, varArg);
    }

    long callLongMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callLongMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callLongMethodV(vm, dvmObject, signature, vaList);
    }

    DvmObject<?>  callObjectMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callObjectMethodV(vm, dvmObject, this, vaList);
    }

    DvmObject<?>  callObjectMethodA(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callObjectMethodA signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    int callIntMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callIntMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callIntMethodV(vm, dvmObject, signature, vaList);
    }

    int callBooleanMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callBooleanMethod signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callBooleanMethod(dvmClass.vm, dvmObject, signature, varArg) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callBooleanMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callBooleanMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callBooleanMethodV(dvmClass.vm, dvmObject, signature, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callIntMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callIntMethod signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callIntMethod(vm, dvmObject, signature, varArg);
    }

    void callVoidMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethod signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).callVoidMethod(vm, dvmObject, signature, varArg);
    }

    int callStaticIntMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticIntMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticIntMethod(vm, dvmClass, signature, varArg);
    }

    int callStaticIntMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticIntMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticIntMethodV(vm, dvmClass, signature, vaList);
    }

    long callStaticLongMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticLongMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticLongMethod(vm, dvmClass, signature, varArg);
    }

    long callStaticLongMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticLongMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticLongMethodV(vm, dvmClass, signature, vaList);
    }

    int CallStaticBooleanMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticBooleanMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticBooleanMethod(vm, dvmClass, signature, varArg) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callStaticBooleanMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticBooleanMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticBooleanMethodV(vm, dvmClass, signature, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    void callStaticVoidMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticVoidMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).callStaticVoidMethod(vm, dvmClass, signature, varArg);
    }

    void callStaticVoidMethodV(VaList vaList) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).callStaticVoidMethodV(vm, dvmClass, this, vaList);
    }

    void callStaticVoidMethodA(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticVoidMethodA signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }

    DvmObject<?> newObjectV(VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).newObjectV(vm, dvmClass, this, vaList);
    }

    int newObject(VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return vm.addObject(checkJni(vm, dvmClass).newObject(vm, dvmClass, this, varArg), false);
    }

    void callVoidMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    void callVoidMethodA(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    float callFloatMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callFloatMethodV signature=" + signature + ", dvmObject=" + dvmObject);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callFloatMethodV(vm, dvmObject, signature, vaList);
    }

    final DvmObject<?>  toReflectedMethod() {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("toReflectedMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).toReflectedMethod(vm, dvmClass, signature);
    }

    public final String decodeArgsShorty() {
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

    @Override
    public String toString() {
        return getSignature();
    }
}
