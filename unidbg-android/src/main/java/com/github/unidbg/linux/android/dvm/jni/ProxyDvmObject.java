package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.*;

public class ProxyDvmObject extends DvmObject<Object> {

    private static DvmClass getObjectType(VM vm, Class<?> clazz) {
        Class<?> superClass = clazz.getSuperclass();
        DvmClass[] interfaces = new DvmClass[clazz.getInterfaces().length + (superClass == null ? 0 : 1)];
        int i = 0;
        if (superClass != null) {
            interfaces[i++] = getObjectType(vm, superClass);
        }
        for (Class<?> cc : clazz.getInterfaces()) {
            interfaces[i++] = getObjectType(vm, cc);
        }
        return vm.resolveClass(clazz.getName().replace('.', '/'), interfaces);
    }

    /**
     * mapping java object to dvm object
     */
    public static DvmObject<?> createObject(VM vm, Object value) {
        if (value == null) {
            return null;
        }

        if (value instanceof byte[]) {
            return new ByteArray(vm, (byte[]) value);
        }
        if (value instanceof short[]) {
            return new ShortArray(vm, (short[]) value);
        }
        if (value instanceof int[]) {
            return new IntArray(vm, (int[]) value);
        }
        if (value instanceof float[]) {
            return new FloatArray(vm, (float[]) value);
        }
        if (value instanceof double[]) {
            return new DoubleArray(vm, (double[]) value);
        }
        if (value instanceof String) {
            return new StringObject(vm, (String) value);
        }
        Class<?> clazz = value.getClass();
        if (clazz.isArray()) {
            if (clazz.getComponentType().isPrimitive()) {
                throw new UnsupportedOperationException(String.valueOf(value));
            }
            Object[] array = (Object[]) value;
            DvmObject<?>[] dvmArray = new DvmObject[array.length];
            for (int i = 0; i < array.length; i++) {
                dvmArray[i] = createObject(vm, array[i]);
            }
            return new ArrayObject(dvmArray);
        }

        return new ProxyDvmObject(vm, value);
    }

    private ProxyDvmObject(VM vm, Object value) {
        super(getObjectType(vm, value.getClass()), value);
    }

}
