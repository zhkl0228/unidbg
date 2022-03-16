package com.github.unidbg.linux.android.dvm;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

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

    public boolean isStatic() {
        return isStatic;
    }

    final String getSignature() {
        return dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
    }

    private Shorty[] shortyCache;

    public final Shorty decodeShorty() {
        if (shortyCache != null) {
            return shortyCache[0];
        }

        char[] chars = getFieldType().toCharArray();
        List<Shorty> list = new ArrayList<>(chars.length);
        int arrayDimensions = 0;
        boolean isType = false;
        Shorty shorty = null;
        StringBuilder binaryName = new StringBuilder();
        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];

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
                    throw new IllegalStateException("i=" + i + ", char=" + chars[i] + ", fieldType=" + fieldType);
            }

            if (type == '0') {
                continue;
            }

            shorty = new Shorty(arrayDimensions, type);
            list.add(shorty);
            arrayDimensions = 0;
        }
        shortyCache = list.toArray(new Shorty[0]);
        return shortyCache[0];
    }

    DvmObject<?> getStaticObjectField() {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getStaticObjectField(vm, dvmClass, this);
    }

    boolean getStaticBooleanField() {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getStaticBooleanField(vm, dvmClass, this);
    }

    byte getStaticByteField() {
        BaseVM vm = dvmClass.vm;
        return checkJni(vm, dvmClass).getStaticByteField(vm, dvmClass, this);
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

    void setFloatField(DvmObject<?> dvmObject, float value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setFloatField(vm, dvmObject, this, value);
    }
    
    void setDoubleField(DvmObject<?> dvmObject, double value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setDoubleField(vm, dvmObject, this, value);
    }

    void setStaticObjectField(DvmObject<?> value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setStaticObjectField(vm, dvmClass, this, value);
    }

    void setStaticBooleanField(boolean value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setStaticBooleanField(vm, dvmClass, this, value);
    }

    void setStaticIntField(int value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setStaticIntField(vm, dvmClass, this, value);
    }

    void setStaticLongField(long value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setStaticLongField(vm, dvmClass, this, value);
    }

    void setStaticFloatField(float value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setStaticFloatField(vm, dvmClass, this, value);
    }

    void setStaticDoubleField(double value) {
        BaseVM vm = dvmClass.vm;
        checkJni(vm, dvmClass).setStaticDoubleField(vm, dvmClass, this, value);
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
