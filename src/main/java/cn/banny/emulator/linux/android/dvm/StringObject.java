package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.memory.MemoryBlock;

public class StringObject extends DvmObject<String> {

    public StringObject(VM vm, String value) {
        super(vm.resolveClass("java/lang/String"), value);

        if (value == null) {
            throw new NullPointerException();
        }
    }

    MemoryBlock memoryBlock;

}
