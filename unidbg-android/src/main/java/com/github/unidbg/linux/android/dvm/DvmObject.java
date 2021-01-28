package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.util.ArrayList;
import java.util.List;

public class DvmObject<T> extends Hashable {

    private final DvmClass objectType;
    protected T value;
    private final BaseVM vm;

    protected DvmObject(DvmClass objectType, T value) {
        this(objectType == null ? null : objectType.vm, objectType, value);
    }

    private DvmObject(BaseVM vm, DvmClass objectType, T value) {
        this.vm = vm;
        this.objectType = objectType;
        this.value = value;
    }

    public T getValue() {
        return value;
    }

    public DvmClass getObjectType() {
        return objectType;
    }

    protected boolean isInstanceOf(DvmClass dvmClass) {
        return objectType != null && objectType.isInstance(dvmClass);
    }

    @SuppressWarnings("unused")
    public void callJniMethod(Emulator<?> emulator, String method, Object...args) {
        if (objectType == null) {
            throw new IllegalStateException("objectType is null");
        }
        try {
            callJniMethod(emulator, vm, objectType, this, method, args);
        } finally {
            vm.deleteLocalRefs();
        }
    }

    @SuppressWarnings("unused")
    public boolean callJniMethodBoolean(Emulator<?> emulator, String method, Object...args) {
        return callJniMethodInt(emulator, method, args) == VM.JNI_TRUE;
    }

    @SuppressWarnings("unused")
    public int callJniMethodInt(Emulator<?> emulator, String method, Object...args) {
        if (objectType == null) {
            throw new IllegalStateException("objectType is null");
        }
        try {
            return callJniMethod(emulator, vm, objectType, this, method, args).intValue();
        } finally {
            vm.deleteLocalRefs();
        }
    }

    @SuppressWarnings("unused")
    public long callJniMethodLong(Emulator<?> emulator, String method, Object...args) {
        if (objectType == null) {
            throw new IllegalStateException("objectType is null");
        }
        try {
            return callJniMethod(emulator, vm, objectType, this, method, args).longValue();
        } finally {
            vm.deleteLocalRefs();
        }
    }

    @SuppressWarnings("unused")
    public <V extends DvmObject<?>> V callJniMethodObject(Emulator<?> emulator, String method, Object...args) {
        if (objectType == null) {
            throw new IllegalStateException("objectType is null");
        }
        try {
            Number number = callJniMethod(emulator, vm, objectType, this, method, args);
            return objectType.vm.getObject(number.intValue());
        } finally {
            vm.deleteLocalRefs();
        }
    }

    protected static Number callJniMethod(Emulator<?> emulator, VM vm, DvmClass objectType, DvmObject<?> thisObj, String method, Object...args) {
        UnidbgPointer fnPtr = objectType.findNativeFunction(emulator, method);
        vm.addLocalObject(thisObj);
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(thisObj.hashCode());
        if (args != null) {
            for (Object arg : args) {
                if (arg instanceof Boolean) {
                    list.add((Boolean) arg ? VM.JNI_TRUE : VM.JNI_FALSE);
                    continue;
                } else if(arg instanceof Hashable) {
                    list.add(arg.hashCode()); // dvm object

                    if(arg instanceof DvmObject) {
                        vm.addLocalObject((DvmObject<?>) arg);
                    }
                    continue;
                } else if (arg instanceof String) {
                    StringObject str = new StringObject(vm, (String) arg);
                    list.add(str.hashCode());
                    vm.addLocalObject(str);
                    continue;
                } else if(arg instanceof byte[]) {
                    ByteArray array = new ByteArray(vm, (byte[]) arg);
                    list.add(array.hashCode());
                    vm.addLocalObject(array);
                    continue;
                }

                list.add(arg);
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

    protected MemoryBlock memoryBlock;

    protected final UnidbgPointer allocateMemoryBlock(Emulator<?> emulator, int length) {
        if (memoryBlock != null) {
            throw new IllegalStateException("Already allocated array memory");
        }

        memoryBlock = emulator.getMemory().malloc(length, true);
        return memoryBlock.getPointer();
    }

    protected final void freeMemoryBlock(Pointer pointer) {
        if (this.memoryBlock != null && (pointer == null || this.memoryBlock.isSame(pointer))) {
            this.memoryBlock.free();
            this.memoryBlock = null;
        }
    }

    final void onDeleteRef() {
        freeMemoryBlock(null);
    }

}
