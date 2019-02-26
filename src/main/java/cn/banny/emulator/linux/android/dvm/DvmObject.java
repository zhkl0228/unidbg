package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.linux.Module;
import cn.banny.emulator.pointer.UnicornPointer;
import unicorn.UnicornException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DvmObject<T> implements Hashable {

    final DvmClass objectType;
    protected T value;

    public DvmObject(DvmClass objectType, T value) {
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
        throw new UnicornException("isInstanceOf");
    }

    public Number callJniMethod(Emulator emulator, String method, Object...args) {
        UnicornPointer fnPtr = objectType.findNativeFunction(emulator, method);
        List<Object> list = new ArrayList<>(10);
        list.add(objectType.vm.getJNIEnv());
        list.add(this.hashCode());
        if (args != null) {
            Collections.addAll(list, args);
        }
        return Module.emulateFunction(emulator, fnPtr.peer, list.toArray())[0];
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "value=" + value +
                '}';
    }
}
