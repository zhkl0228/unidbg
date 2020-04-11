package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.pointer.UnicornPointer;
import unicorn.UnicornException;

import java.util.ArrayList;
import java.util.List;

public class DvmObject<T> implements Hashable {

    private final DvmClass objectType;
    protected T value;

    protected DvmObject(DvmClass objectType, T value) {
        this.objectType = objectType;
        this.value = value;
    }

    public T getValue() {
        return value;
    }

    public DvmClass getObjectType() {
        return objectType;
    }

    protected boolean isInstanceOf(VM vm, DvmClass dvmClass) {
        throw new UnicornException("isInstanceOf vm=" + vm + ", dvmClass=" + dvmClass);
    }

    @SuppressWarnings("unused")
    public Number callJniMethod(Emulator<?> emulator, String method, Object...args) {
        return callJniMethod(emulator, objectType.vm, objectType, this, method, args);
    }

    protected static Number callJniMethod(Emulator<?> emulator, VM vm, DvmClass objectType, DvmObject<?> thisObj, String method, Object...args) {
        UnicornPointer fnPtr = objectType.findNativeFunction(emulator, method);
        vm.addLocalObject(thisObj);
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(thisObj.hashCode());
        if (args != null) {
            for (Object arg : args) {
                if (arg instanceof Boolean) {
                    list.add((Boolean) arg ? VM.JNI_TRUE : VM.JNI_FALSE);
                    continue;
                }

                list.add(arg);

                if(arg instanceof DvmObject) {
                    vm.addLocalObject((DvmObject<?>) arg);
                }
            }
        }
        return Module.emulateFunction(emulator, fnPtr.peer, list.toArray())[0];
    }

    @Override
    public String toString() {
        if (objectType == null) {
            return getClass().getSimpleName() + "{" +
                    "value=" + value +
                    '}';
        }

        return objectType.getName() + "@" + Integer.toHexString(hashCode());
    }
}
