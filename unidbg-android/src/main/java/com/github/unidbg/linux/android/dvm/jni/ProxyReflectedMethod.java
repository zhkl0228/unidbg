package com.github.unidbg.linux.android.dvm.jni;

import java.lang.annotation.Annotation;
import java.lang.reflect.*;

public class ProxyReflectedMethod {

    int accessFlags;
    private final Method method;

    ProxyReflectedMethod(Method method) {
        this.method = method;
        this.accessFlags = method.getModifiers();
    }

    public int getAccessFlags() {
        return accessFlags;
    }

    public void setAccessFlags(int accessFlags) {
        this.accessFlags = accessFlags;
    }

    public Method getMethod() {
        return method;
    }

    public Class<?> getDeclaringClass() {
        return method.getDeclaringClass();
    }

    public String getName() {
        return method.getName();
    }

    public int getModifiers() {
        return method.getModifiers();
    }

    public TypeVariable<Method>[] getTypeParameters() {
        return method.getTypeParameters();
    }

    public Class<?> getReturnType() {
        return method.getReturnType();
    }

    public Type getGenericReturnType() {
        return method.getGenericReturnType();
    }

    public Class<?>[] getParameterTypes() {
        return method.getParameterTypes();
    }

    public Type[] getGenericParameterTypes() {
        return method.getGenericParameterTypes();
    }

    public Class<?>[] getExceptionTypes() {
        return method.getExceptionTypes();
    }

    public Type[] getGenericExceptionTypes() {
        return method.getGenericExceptionTypes();
    }

    public String toGenericString() {
        return method.toGenericString();
    }

    public Object invoke(Object obj, Object... args) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        return method.invoke(obj, args);
    }

    public boolean isBridge() {
        return method.isBridge();
    }

    public boolean isVarArgs() {
        return method.isVarArgs();
    }

    public boolean isSynthetic() {
        return method.isSynthetic();
    }

    public Object getDefaultValue() {
        return method.getDefaultValue();
    }

    public <T extends Annotation> T getAnnotation(Class<T> annotationClass) {
        return method.getAnnotation(annotationClass);
    }

    public Annotation[] getDeclaredAnnotations() {
        return method.getDeclaredAnnotations();
    }

    public Annotation[][] getParameterAnnotations() {
        return method.getParameterAnnotations();
    }

    public static void setAccessible(AccessibleObject[] array, boolean flag) throws SecurityException {
        AccessibleObject.setAccessible(array, flag);
    }

    public void setAccessible(boolean flag) throws SecurityException {
        method.setAccessible(flag);
    }

    public boolean isAccessible() {
        return method.isAccessible();
    }

    public boolean isAnnotationPresent(Class<? extends Annotation> annotationClass) {
        return method.isAnnotationPresent(annotationClass);
    }

    public Annotation[] getAnnotations() {
        return method.getAnnotations();
    }

}
