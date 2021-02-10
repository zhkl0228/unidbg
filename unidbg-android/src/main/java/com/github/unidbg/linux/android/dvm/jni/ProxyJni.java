package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

class ProxyJni extends JniFunction {

    private static final Log log = LogFactory.getLog(ProxyJni.class);

    private final ProxyClassLoader classLoader;
    private final ProxyDvmObjectVisitor visitor;

    ProxyJni(ProxyClassLoader classLoader, ProxyDvmObjectVisitor visitor) {
        this.classLoader = classLoader;
        this.visitor = visitor;
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findConstructor(clazz, dvmMethod, varArg, visitor);
            Object obj = proxyCall.call(vm, null);
            return ProxyDvmObject.createObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("newObject", e);
        }

        return super.newObject(vm, dvmClass, dvmMethod, varArg);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findConstructor(clazz, dvmMethod, vaList, visitor);
            Object obj = proxyCall.call(vm, null);
            return ProxyDvmObject.createObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("newObjectV", e);
        }

        return super.newObjectV(vm, dvmClass, dvmMethod, vaList);
    }

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, true, visitor);
            return (Float) proxyCall.call(vm, null);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticVoidMethod", e);
        }
        return super.callStaticFloatMethod(vm, dvmClass, dvmMethod, varArg);
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, true, visitor);
            proxyCall.call(vm, null);
            return;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticVoidMethod", e);
        }
        super.callStaticVoidMethod(vm, dvmClass, dvmMethod, varArg);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, true, visitor);
            proxyCall.call(vm, null);
            return;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticVoidMethodV", e);
        }
        super.callStaticVoidMethodV(vm, dvmClass, dvmMethod, vaList);
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, true, visitor);
            Object obj = proxyCall.call(vm, null);
            return obj == null ? Boolean.FALSE : (Boolean) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticBooleanMethod", e);
        }
        return super.callStaticBooleanMethod(vm, dvmClass, dvmMethod, varArg);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, true, visitor);
            Object obj = proxyCall.call(vm, null);
            return obj == null ? Boolean.FALSE : (Boolean) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticBooleanMethodV", e);
        }
        return super.callStaticBooleanMethodV(vm, dvmClass, dvmMethod, vaList);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, true, visitor);
            Object obj = proxyCall.call(vm, null);
            return obj == null ? 0 : (Integer) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticIntMethod", e);
        }
        return super.callStaticIntMethod(vm, dvmClass, dvmMethod, varArg);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, true, visitor);
            Object obj = proxyCall.call(vm, null);
            return obj == null ? 0 : (Integer) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticIntMethodV", e);
        }
        return super.callStaticIntMethodV(vm, dvmClass, dvmMethod, vaList);
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, true, visitor);
            Object obj = proxyCall.call(vm, null);
            return obj == null ? 0 : (Long) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticLongMethod", e);
        }
        return super.callStaticLongMethod(vm, dvmClass, dvmMethod, varArg);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, true, visitor);
            Object obj = proxyCall.call(vm, null);
            return obj == null ? 0 : (Long) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticLongMethodV", e);
        }
        return super.callStaticLongMethodV(vm, dvmClass, dvmMethod, vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, true, visitor);
            Object obj = proxyCall.call(vm, null);
            return ProxyDvmObject.createObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticObjectMethod", e);
        }
        return super.callStaticObjectMethod(vm, dvmClass, dvmMethod, varArg);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, true, visitor);
            Object obj = proxyCall.call(vm, null);
            return ProxyDvmObject.createObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callStaticObjectMethodV", e);
        }
        return super.callStaticObjectMethodV(vm, dvmClass, dvmMethod, vaList);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            proxyCall.call(vm, thisObj);
            return;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callVoidMethod", e);
        }
        super.callVoidMethod(vm, dvmObject, dvmMethod, varArg);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            proxyCall.call(vm, thisObj);
            return;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callVoidMethodV", e);
        }
        super.callVoidMethodV(vm, dvmObject, dvmMethod, vaList);
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(vm, thisObj);
            return obj == null ? Boolean.FALSE : (Boolean) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callBooleanMethod", e);
        }
        return super.callBooleanMethod(vm, dvmObject, dvmMethod, varArg);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(vm, thisObj);
            return obj == null ? Boolean.FALSE : (Boolean) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callBooleanMethodV", e);
        }
        return super.callBooleanMethodV(vm, dvmObject, dvmMethod, vaList);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(vm, thisObj);
            return obj == null ? 0 : (Integer) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callIntMethod", e);
        }
        return super.callIntMethod(vm, dvmObject, dvmMethod, varArg);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(vm, thisObj);
            return obj == null ? 0 : (Integer) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callIntMethodV", e);
        }
        return super.callIntMethodV(vm, dvmObject, dvmMethod, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(vm, thisObj);
            return ProxyDvmObject.createObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callObjectMethod", e);
        }
        return super.callObjectMethod(vm, dvmObject, dvmMethod, varArg);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(vm, thisObj);
            return ProxyDvmObject.createObject(vm, obj);
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callObjectMethodV", e);
        }

        return super.callObjectMethodV(vm, dvmObject, dvmMethod, vaList);
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VarArg varArg) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, varArg, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(vm, thisObj);
            return obj == null ? 0 : (Long) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callLongMethod", e);
        }
        return super.callLongMethod(vm, dvmObject, dvmMethod, varArg);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(vm, thisObj);
            return obj == null ? 0 : (Long) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callLongMethodV", e);
        }
        return super.callLongMethodV(vm, dvmObject, dvmMethod, vaList);
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyCall proxyCall = ProxyUtils.findMethod(clazz, dvmMethod, vaList, false, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = proxyCall.call(vm, thisObj);
            return obj == null ? 0f : (Float) obj;
        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | InstantiationException | NoSuchMethodException e) {
            log.warn("callFloatMethodV", e);
        }
        return super.callFloatMethodV(vm, dvmObject, dvmMethod, vaList);
    }

    @Override
    public DvmObject<?> toReflectedMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            List<Class<?>> classes = new ArrayList<>(10);
            ProxyUtils.parseMethodArgs(dvmMethod, classes, clazz.getClassLoader());
            Class<?>[] types = classes.toArray(new Class[0]);
            Method method = ProxyUtils.matchMethodTypes(clazz, dvmMethod.getMethodName(), types, dvmMethod.isStatic());
            return ProxyDvmObject.createObject(vm, new ProxyReflectedMethod(method));
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            log.warn("toReflectedMethod", e);
        }

        return super.toReflectedMethod(vm, dvmClass, dvmMethod);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            Object obj = field.get(thisObj);
            return ProxyDvmObject.createObject(vm, obj);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getObjectField: " + dvmField, e);
        }

        return super.getObjectField(vm, dvmObject, dvmField);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
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
    public float getFloatField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            return field.getFloat(thisObj);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getFloatField: " + dvmField, e);
        }

        return super.getFloatField(vm, dvmObject, dvmField);
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            return field.getBoolean(thisObj);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getBooleanField: " + dvmField, e);
        }
        return super.getBooleanField(vm, dvmObject, dvmField);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            return field.getInt(thisObj);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getIntField: " + dvmField, e);
        }
        return super.getIntField(vm, dvmObject, dvmField);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, int value) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            field.setInt(thisObj, value);
            return;
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("setIntField: " + dvmField, e);
        }
        super.setIntField(vm, dvmObject, dvmField, value);
    }

    @Override
    public void setDoubleField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, double value) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            field.setDouble(thisObj, value);
            return;
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("setDoubleField: " + dvmField, e);
        }
        super.setDoubleField(vm, dvmObject, dvmField, value);
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, long value) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            field.setLong(thisObj, value);
            return;
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("setLongField: " + dvmField, e);
        }
        super.setLongField(vm, dvmObject, dvmField, value);
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, boolean value) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            field.setBoolean(thisObj, value);
            return;
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("setBooleanField: " + dvmField, e);
        }
        super.setBooleanField(vm, dvmObject, dvmField, value);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, DvmField dvmField, DvmObject<?> value) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmObject.getObjectType().getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            Object thisObj = dvmObject.getValue();
            if (thisObj == null) {
                throw new IllegalStateException("obj is null: " + dvmObject);
            }
            field.setObject(thisObj, value == null ? null : value.getValue());
            return;
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("setObjectField: " + dvmField, e);
        }
        super.setObjectField(vm, dvmObject, dvmField, value);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            Object obj = field.get(null);
            return ProxyDvmObject.createObject(vm, obj);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getStaticObjectField", e);
        }

        return super.getStaticObjectField(vm, dvmClass, dvmField);
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            return field.getBoolean(null);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getStaticBooleanField", e);
        }

        return super.getStaticBooleanField(vm, dvmClass, dvmField);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            return field.getInt(null);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getStaticIntField", e);
        }

        return super.getStaticIntField(vm, dvmClass, dvmField);
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, DvmField dvmField) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            return field.getLong(null);
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("getStaticLongField", e);
        }
        return super.getStaticLongField(vm, dvmClass, dvmField);
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, int value) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            field.setInt(null, value);
            return;
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("setStaticIntField", e);
        }
        super.setStaticIntField(vm, dvmClass, dvmField, value);
    }

    @Override
    public void setStaticLongField(BaseVM vm, DvmClass dvmClass, DvmField dvmField, long value) {
        try {
            Class<?> clazz = classLoader.loadClass(dvmClass.getName());
            ProxyField field = ProxyUtils.findField(clazz, dvmField, visitor);
            field.setLong(null, value);
            return;
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            log.warn("setStaticLongField", e);
        }
        super.setStaticLongField(vm, dvmClass, dvmField, value);
    }
}
