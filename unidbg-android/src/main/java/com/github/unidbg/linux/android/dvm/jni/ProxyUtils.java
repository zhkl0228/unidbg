package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.DvmMethod;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VarArg;

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
                    DvmObject<?> obj = varArg.getObject(offset);
                    classes.add(obj.getValue().getClass());
                    args.add(obj.getValue());
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

    static ProxyCall findMethod(Class<?> clazz, DvmMethod dvmMethod, VarArg varArg) throws NoSuchMethodException {
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, varArg);
        Method method = clazz.getDeclaredMethod(dvmMethod.getMethodName(), classes.toArray(new Class[0]));
        return new ProxyMethod(method, args.toArray());
    }

}
