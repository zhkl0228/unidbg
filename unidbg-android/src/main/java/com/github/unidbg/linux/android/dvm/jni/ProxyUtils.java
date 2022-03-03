package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmField;
import com.github.unidbg.linux.android.dvm.DvmMethod;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.Shorty;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.VarArg;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

class ProxyUtils {

    private static void parseMethodArgs(DvmMethod dvmMethod, List<Class<?>> classes, List<Object> args, VarArg varArg, ClassLoader classLoader) {
        Shorty[] shorties = dvmMethod.decodeArgsShorty();
        for (int i = 0; i < shorties.length; i++) {
            Shorty shorty = shorties[i];
            switch (shorty.getType()) {
                case 'B':
                    classes.add(byte.class);
                    args.add((byte) varArg.getIntArg(i));
                    break;
                case 'C':
                    classes.add(char.class);
                    args.add((char) varArg.getIntArg(i));
                    break;
                case 'I':
                    classes.add(int.class);
                    args.add(varArg.getIntArg(i));
                    break;
                case 'S':
                    classes.add(short.class);
                    args.add((short) varArg.getIntArg(i));
                    break;
                case 'Z':
                    classes.add(boolean.class);
                    int value = varArg.getIntArg(i);
                    args.add(BaseVM.valueOf(value));
                    break;
                case 'F':
                    classes.add(float.class);
                    args.add(varArg.getFloatArg(i));
                    break;
                case 'L':
                    DvmObject<?> dvmObject = varArg.getObjectArg(i);
                    if (dvmObject == null) {
                        classes.add(shorty.decodeType(classLoader));
                        args.add(null);
                    } else {
                        Object obj = unpack(dvmObject);
                        classes.add(obj.getClass());
                        args.add(obj);
                    }
                    break;
                case 'D':
                    classes.add(double.class);
                    args.add(varArg.getDoubleArg(i));
                    break;
                case 'J':
                    classes.add(long.class);
                    args.add(varArg.getLongArg(i));
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

    static Member matchMethodTypes(Class<?> clazz, String methodName, Class<?>[] types, boolean isStatic) throws NoSuchMethodException {
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
        if (!isStatic) {
            for (Method method : clazz.getDeclaredMethods()) {
                if (method.getParameterTypes().length == types.length &&
                        methodName.equals(method.getName()) &&
                        Modifier.isStatic(method.getModifiers())) {
                    methods.add(method);
                }
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

        if ("<init>".equals(methodName)) {
            for (Constructor<?> constructor : clazz.getDeclaredConstructors()) {
                if (matchesTypes(constructor.getParameterTypes(), types, true)) {
                    return constructor;
                }
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

    public static ProxyCall findAllocConstructor(Class<?> clazz, ProxyDvmObjectVisitor visitor) throws NoSuchMethodException {
        Constructor<?> constructor = matchConstructorTypes(clazz, new Class<?>[0]);
        return new ProxyConstructor(visitor, constructor, new Object[0]);
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

    static ProxyCall findMethod(Class<?> clazz, DvmMethod dvmMethod, VarArg varArg, boolean isStatic, ProxyDvmObjectVisitor visitor) throws NoSuchMethodException {
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, varArg, clazz.getClassLoader());
        if (dvmMethod.member != null) {
            return new ProxyMethod(visitor, dvmMethod.member, args.toArray());
        }
        Class<?>[] types = classes.toArray(new Class[0]);
        Member method = matchMethodTypes(clazz, dvmMethod.getMethodName(), types, isStatic);
        dvmMethod.setMember(method);
        return new ProxyMethod(visitor, method, args.toArray());
    }

    static ProxyCall findMethod(Class<?> clazz, DvmMethod dvmMethod, VaList vaList, boolean isStatic, ProxyDvmObjectVisitor visitor) throws NoSuchMethodException {
        List<Class<?>> classes = new ArrayList<>(10);
        List<Object> args = new ArrayList<>(10);
        parseMethodArgs(dvmMethod, classes, args, vaList, clazz.getClassLoader());
        if (dvmMethod.member != null) {
            return new ProxyMethod(visitor, dvmMethod.member, args.toArray());
        }
        Class<?>[] types = classes.toArray(new Class[0]);
        Member method = matchMethodTypes(clazz, dvmMethod.getMethodName(), types, isStatic);
        dvmMethod.setMember(method);
        return new ProxyMethod(visitor, method, args.toArray());
    }

    static Field matchField(Class<?> clazz, String fieldName, Class<?> fieldType, boolean isStatic) throws NoSuchFieldException {
        List<Field> fields = new ArrayList<>();
        if (isStatic) {
            for (Field field : clazz.getFields()) {
                if (fieldName.equals(field.getName()) &&
                        Modifier.isStatic(field.getModifiers())) {
                    fields.add(field);
                }
            }
        }
        for (Field field : clazz.getDeclaredFields()) {
            if (fieldName.equals(field.getName()) &&
                    isStatic == Modifier.isStatic(field.getModifiers())) {
                fields.add(field);
            }
        }
        if (!isStatic) {
            for (Field field : clazz.getDeclaredFields()) {
                if (fieldName.equals(field.getName()) &&
                        Modifier.isStatic(field.getModifiers())) {
                    fields.add(field);
                }
            }
        }
        for (Field field : fields) {
            if (matchesTypes(new Class[] { field.getType() }, new Class[] { fieldType }, true)) {
                return field;
            }
        }
        for (Field field : fields) {
            if (matchesTypes(new Class[] { field.getType() }, new Class[] { fieldType }, false)) {
                return field;
            }
        }

        Class<?> parentClass = clazz.getSuperclass();
        if (!isStatic && parentClass != null) {
            try {
                return matchField(parentClass, fieldName, fieldType, false);
            } catch(NoSuchFieldException ignored) {}
        }

        throw new NoSuchFieldException(clazz.getName() + "." + fieldName + ":" + fieldType);
    }

    static ProxyField findField(Class<?> clazz, DvmField dvmField, ProxyDvmObjectVisitor visitor) throws NoSuchFieldException {
        if (dvmField.filed != null) {
            return new ProxyField(visitor, dvmField.filed);
        }

        Shorty shorty = dvmField.decodeShorty();
        Field field = matchField(clazz, dvmField.getFieldName(), shorty.decodeType(clazz.getClassLoader()), dvmField.isStatic());
        dvmField.setFiled(field);
        return new ProxyField(visitor, field);
    }
}
