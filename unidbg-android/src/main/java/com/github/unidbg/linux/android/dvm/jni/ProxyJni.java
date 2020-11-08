package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.lang.reflect.InvocationTargetException;

class ProxyJni extends JniFunction {

    private static final Log log = LogFactory.getLog(ProxyJni.class);

    private final ClassLoader classLoader;

    ProxyJni(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findConstructor(clazz, dvmMethod, varArg);
            Object obj = proxyCall.call(null);
            return ProxyDvmObject.createDvmObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("newObject", e);
        }

        return super.newObject(vm, dvmClass, dvmMethod, varArg);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findConstructor(clazz, dvmMethod, vaList);
            Object obj = proxyCall.call(null);
            return ProxyDvmObject.createDvmObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("newObjectV", e);
        }

        return super.newObjectV(vm, dvmClass, dvmMethod, vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg);
            Object obj = proxyCall.call(null);
            return obj == null ? null : ProxyDvmObject.createDvmObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticObjectMethod", e);
        }
        return super.callStaticObjectMethod(vm, dvmClass, dvmMethod, varArg);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList);
            proxyCall.call(null);
            return;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticVoidMethodV", e);
        }
        super.callStaticVoidMethodV(vm, dvmClass, dvmMethod, vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList);
            Object obj = proxyCall.call(null);
            return obj == null ? null : ProxyDvmObject.createDvmObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticObjectMethodV", e);
        }
        return super.callStaticObjectMethodV(vm, dvmClass, dvmMethod, vaList);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList);
            return (Long) proxyCall.call(null);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticLongMethodV", e);
        }
        return super.callStaticLongMethodV(vm, dvmClass, dvmMethod, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(thisObj);
            return obj == null ? null : ProxyDvmObject.createDvmObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callObjectMethod", e);
        }
        return super.callObjectMethod(vm, dvmObject, dvmMethod, varArg);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(thisObj);
            return obj == null ? null : ProxyDvmObject.createDvmObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callObjectMethodV", e);
        }

        return super.callObjectMethodV(vm, dvmObject, dvmMethod, vaList);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = field.get(thisObj);
            return obj == null ? null : ProxyDvmObject.createDvmObject(vm, obj);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getObjectField: " + dvmField, e);
        }

        return super.getObjectField(vm, dvmObject, dvmField);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            return field.getLong(thisObj);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getLongField: " + dvmField, e);
        }

        return super.getLongField(vm, dvmObject, dvmField);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField);
            Object obj = field.get(null);
            return obj == null ? null : ProxyDvmObject.createDvmObject(vm, obj);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getStaticObjectField", e);
        }

        return super.getStaticObjectField(vm, dvmClass, dvmField);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField);
            Object obj = field.get(null);
            return (Integer) obj;
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getStaticIntField", e);
        }

        return super.getStaticIntField(vm, dvmClass, dvmField);
    }
}
