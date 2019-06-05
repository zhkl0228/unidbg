package cn.banny.unidbg.linux.android.dvm;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.linux.LinuxModule;
import cn.banny.unidbg.pointer.UnicornPointer;
import unicorn.UnicornException;

import java.util.ArrayList;
import java.util.List;

public class DvmObject<T> implements Hashable {

    final DvmClass objectType;
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
        throw new UnicornException("isInstanceOf");
    }

    public Number callJniMethod(Emulator emulator, String method, Object...args) {
        UnicornPointer fnPtr = objectType.findNativeFunction(emulator, method);
        List<Object> list = new ArrayList<>(10);
        list.add(objectType.vm.getJNIEnv());
        list.add(this.hashCode());
        objectType.vm.addLocalObject(this);
        if (args != null) {
            for (Object arg : args) {
                list.add(arg);

                if(arg instanceof DvmObject) {
                    objectType.vm.addLocalObject((DvmObject) arg);
                }
            }
        }
        return LinuxModule.emulateFunction(emulator, fnPtr.peer, list.toArray())[0];
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "value=" + value +
                '}';
    }
}
