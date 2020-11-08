package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

class ProxyUtils {

    private static void parseMethodArgs(DvmMethod dvmMethod, List<Class<?>> classes, List<Object> args, VarArg varArg) {
        String shorty = dvmMethod.decodeArgsShorty();
        char[] chars = shorty.toCharArray();
        int offset = 0;
        for (char c : chars) {
            switch (c) {
                case 'B':
                    classes.add(byte.class);
                    args.add((byte) varArg.getInt(offset));
                    offset++;
                    break;
                case 'C':
                    classes.add(char.class);
                    args.add((char) varArg.getInt(offset));
                    offset++;
                    break;
                case 'I':
                    classes.add(int.class);
                    args.add(varArg.getInt(offset));
                    offset++;
                    break;
                case 'S':
                    classes.add(short.class);
                    args.add((short) varArg.getInt(offset));
                    offset++;
                    break;
                case 'Z':
                    classes.add(boolean.class);
                    args.add(varArg.getInt(offset) == VM.JNI_TRUE);
                    offset++;
                    break;
                /*case 'F':
                    args.add(varArg.getFloat(offset));
                    offset++;
                    break;*/
                case 'L':
                    DvmObject<?> dvmObject = varArg.getObject(offset);
                    if (dvmObject == null) {
                        throw new IllegalStateException();
                    }
                    Object obj = dvmObject.getValue();
                    classes.add(obj.getClass());
                    args.add(obj);
                    offset++;
                    break;
                /*case 'D':
                    args.add(varArg.getDouble(offset));
                    offset++;
                    break;*/
                /*case 'J':
                    args.add(varArg.getLong(offset));
                    offset++;
                    break;*/
                default:
                    throw new IllegalStateException("c=" + c);
            }
        }
    }

    private static void parseMethodArgs(DvmMethod dvmMethod, List<Class<?>> classes, List<Object> args, VaList vaList) {
        String shorty = dvmMethod.decodeArgsShorty();
        char[] chars = shorty.toCharArray();
        int offset = 0;
        for (char c : chars) {
            switch (c) {
                case 'B':
                    classes.add(byte.class);
                    args.add((byte) vaList.getInt(offset));
                    offset += 4;
                    break;
                case 'C':
                    classes.add(char.class);
                    args.add((char) vaList.getInt(offset));
                    offset += 4;
                    break;
                case 'I':
                    classes.add(int.class);
                    args.add(vaList.getInt(offset));
                    offset += 4;
                    break;
                case 'S':
                    classes.add(short.class);
                    args.add((short) vaList.getInt(offset));
                    offset += 4;
                    break;
                case 'Z':
                    classes.add(boolean.class);
                    args.add(vaList.getInt(offset) == VM.JNI_TRUE);
                    offset += 4;
                    break;
                case 'F':
                    classes.add(float.class);
                    args.add(vaList.getFloat(offset));
                    offset += 4;
                    break;
                case 'L':
                    DvmObject<?> dvmObject = vaList.getObject(offset);
                    if (dvmObject == null) {
                        throw new IllegalStateException();
                    }
                    Object obj = dvmObject.getValue();
                    classes.add(obj.getClass());
                    args.add(obj);
                    offset += 4;
                    break;
                case 'D':
                    classes.add(double.class);
                    args.add(vaList.getDouble(offset));
                    offset += 8;
                    break;
                case 'J':
                    classes.add(long.class);
                    args.add(vaList.getLong(offset));
                    offset += 8;
                    break;
                default:
                    throw new IllegalStateException("c=" + c);
            }
        }
    }

    static ProxyCall findConstructor(Class<?> clazz, DvmMethod dvmMethod, VarArg varArg) throws NoSuchMethodException {
        if (!"<init>".equals(dvmMethod.getMethodName())) {
            throw new IllegalStateException(dvmMethod.getMethodName());
        }
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, varArg);
        Constructor<?> constructor = clazz.getDeclaredConstructor(classes.toArray(new Class[0]));
        return new ProxyConstructor(constructor, args.toArray());
    }

    static ProxyCall findConstructor(Class<?> clazz, DvmMethod dvmMethod, VaList vaList) throws NoSuchMethodException {
        if (!"<init>".equals(dvmMethod.getMethodName())) {
            throw new IllegalStateException(dvmMethod.getMethodName());
        }
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, vaList);
        Constructor<?> constructor = clazz.getDeclaredConstructor(classes.toArray(new Class[0]));
        return new ProxyConstructor(constructor, args.toArray());
    }

    static ProxyCall findMethod(Class<?> clazz, DvmMethod dvmMethod, VarArg varArg) throws NoSuchMethodException {
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, varArg);
        Method method = clazz.getDeclaredMethod(dvmMethod.getMethodName(), classes.toArray(new Class[0]));
        return new ProxyMethod(method, args.toArray());
    }

    static ProxyCall findMethod(Class<?> clazz, DvmMethod dvmMethod, VaList vaList) throws NoSuchMethodException {
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, vaList);
        Method method = clazz.getDeclaredMethod(dvmMethod.getMethodName(), classes.toArray(new Class[0]));
        return new ProxyMethod(method, args.toArray());
    }

}
