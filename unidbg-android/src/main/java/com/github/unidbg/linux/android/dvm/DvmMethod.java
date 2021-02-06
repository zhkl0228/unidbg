package com.github.unidbg.linux.android.dvm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Member;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

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
        // bug fix for android UUID.createString
        if (UUID.class.getName().equals(dvmClass.getName()) && "createString".equals(methodName)) {
            return "toString";
        }
        return methodName;
    }

    public String getArgs() {
        return args;
    }

    final String getSignature() {
        return dvmClass.getClassName() + "->" + methodName + args;
    }

    public boolean isStatic() {
        return isStatic;
    }

    DvmObject<?>  callStaticObjectMethod(VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticObjectMethod(vm, dvmClass, this, varArg);
    }

    DvmObject<?>  callStaticObjectMethodV(VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticObjectMethodV(vm, dvmClass, this, vaList);
    }

    DvmObject<?>  callStaticObjectMethodA(VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticObjectMethodV(vm, dvmClass, this, vaList);
    }

    DvmObject<?>  callObjectMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callObjectMethod(vm, dvmObject, this, varArg);
    }

    long callLongMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callLongMethod(vm, dvmObject, this, varArg);
    }

    long callLongMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callLongMethodV(vm, dvmObject, this, vaList);
    }

    DvmObject<?>  callObjectMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callObjectMethodV(vm, dvmObject, this, vaList);
    }

    DvmObject<?>  callObjectMethodA(DvmObject<?>  dvmObject, VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callObjectMethodV(vm, dvmObject, this, vaList);
    }

    int callIntMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callIntMethodV(vm, dvmObject, this, vaList);
    }

    int callBooleanMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callBooleanMethod(vm, dvmObject, this, varArg) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callBooleanMethodV(DvmObject<?>  dvmObject, VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callBooleanMethodV(vm, dvmObject, this, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callBooleanMethodA(DvmObject<?>  dvmObject, VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callBooleanMethodV(vm, dvmObject, this, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callIntMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callIntMethod(vm, dvmObject, this, varArg);
    }

    void callVoidMethod(DvmObject<?>  dvmObject, VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).callVoidMethod(vm, dvmObject, this, varArg);
    }

    int callStaticIntMethod(VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticIntMethod(vm, dvmClass, this, varArg);
    }

    int callStaticIntMethodV(VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticIntMethodV(vm, dvmClass, this, vaList);
    }

    long callStaticLongMethod(VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticLongMethod(vm, dvmClass, this, varArg);
    }

    long callStaticLongMethodV(VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticLongMethodV(vm, dvmClass, this, vaList);
    }

    int CallStaticBooleanMethod(VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticBooleanMethod(vm, dvmClass, this, varArg) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callStaticBooleanMethodV(VaList vaList) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticBooleanMethodV(vm, dvmClass, this, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    float callStaticFloatMethod(VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callStaticFloatMethod(vm, dvmClass, this, varArg);
    }

    void callStaticVoidMethod(VarArg varArg) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).callStaticVoidMethod(vm, dvmClass, this, varArg);
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
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).callVoidMethodV(vm, dvmObject, this, vaList);
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
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).callFloatMethodV(vm, dvmObject, this, vaList);
    }

    final DvmObject<?>  toReflectedMethod() {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).toReflectedMethod(vm, dvmClass, this);
    }

    private Shorty[] shortyCache;

    public final Shorty[] decodeArgsShorty() {
        if (shortyCache != null) {
            return shortyCache;
        }

        char[] chars = args.toCharArray();
        List<Shorty> list = new ArrayList<>(chars.length);
        int arrayDimensions = 0;
        boolean isType = false;
        Shorty shorty = null;
        StringBuilder binaryName = new StringBuilder();
        for (int i = 1; i < chars.length; i++) {
            char c = chars[i];
            if (c == ')') {
                break;
            }

            if (isType) {
                if (c == ';') {
                    isType = false;
                    shorty.setBinaryName(binaryName.toString());
                    binaryName.delete(0, binaryName.length());
                } else {
                    binaryName.append(c);
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
                    arrayDimensions++;
                    break;
                default:
                    throw new IllegalStateException("i=" + i + ", char=" + chars[i] + ", args=" + args);
            }

            if (type == '0') {
                continue;
            }

            shorty = new Shorty(arrayDimensions, type);
            list.add(shorty);
            arrayDimensions = 0;
        }
        shortyCache = list.toArray(new Shorty[0]);
        return shortyCache;
    }

    public Member member;

    public void setMember(Member member) {
        ((AccessibleObject) member).setAccessible(true);
        if (Modifier.isStatic(member.getModifiers()) ^ isStatic) {
            throw new IllegalStateException(toString());
        }
        if (member.getDeclaringClass().getName().equals(dvmClass.getName())) {
            this.member = member;
        }
    }

    @Override
    public String toString() {
        return getSignature();
    }
}
