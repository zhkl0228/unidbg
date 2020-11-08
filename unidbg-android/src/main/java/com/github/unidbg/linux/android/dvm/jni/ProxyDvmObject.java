package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;

class ProxyDvmObject extends DvmObject<Object> {

    private static DvmClass getObjectType(BaseVM vm, Class<?> clazz) {
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

    ProxyDvmObject(BaseVM vm, Object value) {
        super(getObjectType(vm, value.getClass()), value);
    }

}
