package com.github.unidbg.linux.android.dvm.jni;

import java.lang.annotation.Annotation;
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Type;

public class ProxyReflectedConstructor {

    private final Constructor<?> constructor;

    public ProxyReflectedConstructor(Constructor<?> constructor) {
        this.constructor = constructor;
    }

    public Class<?> getDeclaringClass() {
        return constructor.getDeclaringClass();
    }

    public String getName() {
        return constructor.getName();
    }

    public int getModifiers() {
        return constructor.getModifiers();
    }

    public Class<?>[] getParameterTypes() {
        return constructor.getParameterTypes();
    }

    public Type[] getGenericParameterTypes() {
        return constructor.getGenericParameterTypes();
    }

    public Class<?>[] getExceptionTypes() {
        return constructor.getExceptionTypes();
    }

    public Type[] getGenericExceptionTypes() {
        return constructor.getGenericExceptionTypes();
    }

    public String toGenericString() {
        return constructor.toGenericString();
    }

    public Object newInstance(Object... initargs) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        return constructor.newInstance(initargs);
    }

    public boolean isVarArgs() {
        return constructor.isVarArgs();
    }

    public boolean isSynthetic() {
        return constructor.isSynthetic();
    }

    public <T extends Annotation> T getAnnotation(Class<T> annotationClass) {
        return constructor.getAnnotation(annotationClass);
    }

    public Annotation[] getDeclaredAnnotations() {
        return constructor.getDeclaredAnnotations();
    }

    public Annotation[][] getParameterAnnotations() {
        return constructor.getParameterAnnotations();
    }

    public static void setAccessible(AccessibleObject[] array, boolean flag) throws SecurityException {
        AccessibleObject.setAccessible(array, flag);
    }

    public void setAccessible(boolean flag) throws SecurityException {
        constructor.setAccessible(flag);
    }

    public boolean isAccessible() {
        return constructor.isAccessible();
    }

    public boolean isAnnotationPresent(Class<? extends Annotation> annotationClass) {
        return constructor.isAnnotationPresent(annotationClass);
    }

    public Annotation[] getAnnotations() {
        return constructor.getAnnotations();
    }
}
