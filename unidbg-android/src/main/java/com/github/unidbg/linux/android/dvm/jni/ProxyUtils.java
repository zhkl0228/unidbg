package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

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
                        classes.add(null);
                        args.add(null);
                    } else {
                        Object obj = dvmObject.getValue();
                        classes.add(obj.getClass());
                        args.add(unpack(dvmObject));
                    }
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
                        classes.add(null);
                        args.add(null);
                    } else {
                        Object obj = dvmObject.getValue();
                        classes.add(obj.getClass());
                        args.add(unpack(dvmObject));
                    }
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

    private static Object unpack(DvmObject<?> dvmObject) {
        if (dvmObject == null) {
            return null;
        }
        Object obj = dvmObject.getValue();
        if (obj instanceof DvmObject) {
            return unpack((DvmObject<?>) obj);
        } else {
            Class<?> clazz = obj.getClass();
            if (clazz.isArray() && DvmObject.class.isAssignableFrom(clazz.getComponentType())) {
                Object[] dvmArray = (Object[]) obj;
                Object[] array = new Object[dvmArray.length];
                for (int i = 0; i < dvmArray.length; i++) {
                    DvmObject<?> dvm = (DvmObject<?>) dvmArray[i];
                    array[i] = unpack(dvm);
                }
                return array;
            }

            return obj;
        }
    }

    static void parseMethodArgs(DvmMethod dvmMethod, List<Class<?>> classes) {
        String shorty = dvmMethod.decodeArgsShorty();
        char[] chars = shorty.toCharArray();
        for (char c : chars) {
            switch (c) {
                case 'B':
                    classes.add(byte.class);
                    break;
                case 'C':
                    classes.add(char.class);
                    break;
                case 'I':
                    classes.add(int.class);
                    break;
                case 'S':
                    classes.add(short.class);
                    break;
                case 'Z':
                    classes.add(boolean.class);
                    break;
                case 'F':
                    classes.add(float.class);
                    break;
                case 'L':
                    classes.add(null);
                    break;
                case 'D':
                    classes.add(double.class);
                    break;
                case 'J':
                    classes.add(long.class);
                    break;
                default:
                    throw new IllegalStateException("c=" + c);
            }
        }
    }

    private static boolean matchesTypes(Class<?>[] parameterTypes, Class<?>[] types, boolean strict) {
        if (parameterTypes.length != types.length) {
            return false;
        }
        for (int i = 0; i < types.length; i++) {
            if (types[i] == null) {
                continue;
            }

            if (strict) {
                if (parameterTypes[i] != types[i]) {
                    return false;
                }
            } else {
                if (!parameterTypes[i].isAssignableFrom(types[i])) {
                    return false;
                }
            }
        }
        return true;
    }

    static Method matchMethodTypes(Class<?> clazz, String methodName, Class<?>[] types) throws NoSuchMethodException {
        List<Method> methods = new ArrayList<>();
        for (Method method : clazz.getMethods()) {
            if (method.getParameterTypes().length == types.length && methodName.equals(method.getName())) {
                methods.add(method);
            }
        }
        for (Method method : clazz.getDeclaredMethods()) {
            if (method.getParameterTypes().length == types.length && methodName.equals(method.getName())) {
                methods.add(method);
            }
        }
        for (Method method : methods) {
            if (matchesTypes(method.getParameterTypes(), types, true)) {
                return method;
            }
        }
        for (Method method : methods) {
            if (matchesTypes(method.getParameterTypes(), types, false)) {
                return method;
            }
        }
        throw new NoSuchMethodException(Arrays.toString(types));
    }

    private static Constructor<?> matchConstructorTypes(Class<?> clazz, Class<?>[] types) throws NoSuchMethodException {
        for (Constructor<?> constructor : clazz.getDeclaredConstructors()) {
            if (matchesTypes(constructor.getParameterTypes(), types, true)) {
                return constructor;
            }
        }
        for (Constructor<?> constructor : clazz.getDeclaredConstructors()) {
            if (matchesTypes(constructor.getParameterTypes(), types, false)) {
                return constructor;
            }
        }
        throw new NoSuchMethodException(Arrays.toString(types));
    }

    static ProxyCall findConstructor(Class<?> clazz, DvmMethod dvmMethod, VarArg varArg) throws NoSuchMethodException {
        if (!"<init>".equals(dvmMethod.getMethodName())) {
            throw new IllegalStateException(dvmMethod.getMethodName());
        }
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, varArg);
        if (dvmMethod.member != null) {
            return new ProxyConstructor((Constructor<?>) dvmMethod.member, args.toArray());
        }
        Class<?>[] types = classes.toArray(new Class<?>[0]);
        Constructor<?> constructor = matchConstructorTypes(clazz, types);
        dvmMethod.setMember(constructor);
        return new ProxyConstructor(constructor, args.toArray());
    }

    static ProxyCall findConstructor(Class<?> clazz, DvmMethod dvmMethod, VaList vaList) throws NoSuchMethodException {
        if (!"<init>".equals(dvmMethod.getMethodName())) {
            throw new IllegalStateException(dvmMethod.getMethodName());
        }
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, vaList);
        if (dvmMethod.member != null) {
            return new ProxyConstructor((Constructor<?>) dvmMethod.member, args.toArray());
        }
        Class<?>[] types = classes.toArray(new Class<?>[0]);
        Constructor<?> constructor = matchConstructorTypes(clazz, types);
        dvmMethod.setMember(constructor);
        return new ProxyConstructor(constructor, args.toArray());
    }

    static ProxyCall findMethod(Class<?> clazz, DvmMethod dvmMethod, VarArg varArg) throws NoSuchMethodException {
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, varArg);
        if (dvmMethod.member != null) {
            return new ProxyMethod((Method) dvmMethod.member, args.toArray());
        }
        Class<?>[] types = classes.toArray(new Class[0]);
        Method method = matchMethodTypes(clazz, dvmMethod.getMethodName(), types);
        dvmMethod.setMember(method);
        return new ProxyMethod(method, args.toArray());
    }

    static ProxyCall findMethod(Class<?> clazz, DvmMethod dvmMethod, VaList vaList) throws NoSuchMethodException {
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, vaList);
        if (dvmMethod.member != null) {
            return new ProxyMethod((Method) dvmMethod.member, args.toArray());
        }
        Class<?>[] types = classes.toArray(new Class[0]);
        Method method = matchMethodTypes(clazz, dvmMethod.getMethodName(), types);
        dvmMethod.setMember(method);
        return new ProxyMethod(method, args.toArray());
    }

    static ProxyField findField(Class<?> clazz, DvmField dvmField) throws NoSuchFieldException {
        if (dvmField.filed != null) {
            return new ProxyField(dvmField.filed);
        }
        String fieldName = dvmField.getFieldName();
        try {
            Field field = clazz.getField(fieldName);
            dvmField.setFiled(field);
            return new ProxyField(field);
        } catch (NoSuchFieldException e) {
            Field field = clazz.getDeclaredField(fieldName);
            dvmField.setFiled(field);
            return new ProxyField(field);
        }
    }

}
