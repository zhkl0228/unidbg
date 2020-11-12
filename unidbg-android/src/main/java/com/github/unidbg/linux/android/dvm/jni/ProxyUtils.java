package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.*;

import java.lang.reflect.Array;
import java.lang.reflect.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

class ProxyUtils {

    private static void parseMethodArgs(DvmMethod dvmMethod, List<Class<?>> classes, List<Object> args, VarArg varArg, ClassLoader classLoader) {
        Shorty[] shorties = dvmMethod.decodeArgsShorty();
        int offset = 0;
        for (Shorty shorty : shorties) {
            switch (shorty.getType()) {
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
                        classes.add(shorty.decodeType(classLoader));
                        args.add(null);
                    } else {
                        Object obj = unpack(dvmObject);
                        classes.add(obj.getClass());
                        args.add(obj);
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
                    throw new IllegalStateException("c=" + shorty.getType());
            }
        }
    }

    private static void parseMethodArgs(DvmMethod dvmMethod, List<Class<?>> classes, List<Object> args, VaList vaList, ClassLoader classLoader) {
        Shorty[] shorties = dvmMethod.decodeArgsShorty();
        int offset = 0;
        for (Shorty shorty : shorties) {
            switch (shorty.getType()) {
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
                        classes.add(shorty.decodeType(classLoader));
                        args.add(null);
                    } else {
                        Object obj = unpack(dvmObject);
                        classes.add(obj.getClass());
                        args.add(obj);
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
                    throw new IllegalStateException("c=" + shorty.getType());
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
                Class<?> arrayType = null;
                boolean oneArrayType = false;
                for (int i = 0; i < dvmArray.length; i++) {
                    DvmObject<?> dvm = (DvmObject<?>) dvmArray[i];
                    array[i] = unpack(dvm);
                    if (array[i] == null) {
                        continue;
                    }
                    if (arrayType == null) {
                        arrayType = array[i].getClass();
                        oneArrayType = true;
                    } else if(arrayType != array[i].getClass()) {
                        oneArrayType = false;
                    }
                }
                if (oneArrayType) {
                    Object oneArray = Array.newInstance(arrayType, array.length);
                    for (int i = 0; i < array.length; i++) {
                        Array.set(oneArray, i, array[i]);
                    }
                    return oneArray;
                }
                return array;
            }

            return obj;
        }
    }

    static void parseMethodArgs(DvmMethod dvmMethod, List<Class<?>> classes, ClassLoader classLoader) {
        Shorty[] shorties = dvmMethod.decodeArgsShorty();
        for (Shorty shorty : shorties) {
            Class<?> clazz = shorty.decodeType(classLoader);
            classes.add(clazz);
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

    static Method matchMethodTypes(Class<?> clazz, String methodName, Class<?>[] types, boolean isStatic) throws NoSuchMethodException {
        List<Method> methods = new ArrayList<>();
        if (isStatic) {
            for (Method method : clazz.getMethods()) {
                if (method.getParameterTypes().length == types.length &&
                        methodName.equals(method.getName()) &&
                        Modifier.isStatic(method.getModifiers())) {
                    methods.add(method);
                }
            }
        }
        for (Method method : clazz.getDeclaredMethods()) {
            if (method.getParameterTypes().length == types.length &&
                    methodName.equals(method.getName()) &&
                    isStatic == Modifier.isStatic(method.getModifiers())) {
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

        Class<?> parentClass = clazz.getSuperclass();
        if (!isStatic && parentClass != null) {
            try {
                return matchMethodTypes(parentClass, methodName, types, false);
            } catch(NoSuchMethodException ignored) {}
        }

        throw new NoSuchMethodException(clazz.getName() + "." + methodName + Arrays.toString(types));
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
        throw new NoSuchMethodException(clazz.getName() + ".<init>" + Arrays.toString(types));
    }

    static ProxyCall findConstructor(Class<?> clazz, DvmMethod dvmMethod, VarArg varArg, ProxyDvmObjectVisitor visitor) throws NoSuchMethodException {
        if (!"<init>".equals(dvmMethod.getMethodName())) {
            throw new IllegalStateException(dvmMethod.getMethodName());
        }
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, varArg, clazz.getClassLoader());
        if (dvmMethod.member != null) {
            return new ProxyConstructor(visitor, (Constructor<?>) dvmMethod.member, args.toArray());
        }
        Class<?>[] types = classes.toArray(new Class<?>[0]);
        Constructor<?> constructor = matchConstructorTypes(clazz, types);
        dvmMethod.setMember(constructor);
        return new ProxyConstructor(visitor, constructor, args.toArray());
    }

    static ProxyCall findConstructor(Class<?> clazz, DvmMethod dvmMethod, VaList vaList, ProxyDvmObjectVisitor visitor) throws NoSuchMethodException {
        if (!"<init>".equals(dvmMethod.getMethodName())) {
            throw new IllegalStateException(dvmMethod.getMethodName());
        }
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, vaList, clazz.getClassLoader());
        if (dvmMethod.member != null) {
            return new ProxyConstructor(visitor, (Constructor<?>) dvmMethod.member, args.toArray());
        }
        Class<?>[] types = classes.toArray(new Class<?>[0]);
        Constructor<?> constructor = matchConstructorTypes(clazz, types);
        dvmMethod.setMember(constructor);
        return new ProxyConstructor(visitor, constructor, args.toArray());
    }

    static ProxyCall findMethod(Class<?> clazz, DvmMethod dvmMethod, VarArg varArg, boolean isStatic, ProxyDvmObjectVisitor visitor) throws NoSuchMethodException {
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, varArg, clazz.getClassLoader());
        if (dvmMethod.member != null) {
            return new ProxyMethod(visitor, (Method) dvmMethod.member, args.toArray());
        }
        Class<?>[] types = classes.toArray(new Class[0]);
        Method method = matchMethodTypes(clazz, dvmMethod.getMethodName(), types, isStatic);
        dvmMethod.setMember(method);
        return new ProxyMethod(visitor, method, args.toArray());
    }

    static ProxyCall findMethod(Class<?> clazz, DvmMethod dvmMethod, VaList vaList, boolean isStatic, ProxyDvmObjectVisitor visitor) throws NoSuchMethodException {
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, vaList, clazz.getClassLoader());
        if (dvmMethod.member != null) {
            return new ProxyMethod(visitor, (Method) dvmMethod.member, args.toArray());
        }
        Class<?>[] types = classes.toArray(new Class[0]);
        Method method = matchMethodTypes(clazz, dvmMethod.getMethodName(), types, isStatic);
        dvmMethod.setMember(method);
        return new ProxyMethod(visitor, method, args.toArray());
    }

    static ProxyField findField(Class<?> clazz, DvmField dvmField, ProxyDvmObjectVisitor visitor) throws NoSuchFieldException {
        if (dvmField.filed != null) {
            return new ProxyField(visitor, dvmField.filed);
        }
        String fieldName = dvmField.getFieldName();
        try {
            Field field = clazz.getField(fieldName);
            dvmField.setFiled(field);
            return new ProxyField(visitor, field);
        } catch (NoSuchFieldException e) {
            Field field = clazz.getDeclaredField(fieldName);
            dvmField.setFiled(field);
            return new ProxyField(visitor, field);
        }
    }

}
