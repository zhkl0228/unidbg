package cn.banny.unidbg.linux.android.dvm;

import cn.banny.unidbg.pointer.UnicornPointer;

public class VaList {

    private final BaseVM vm;
    private final UnicornPointer va_list;

    VaList(BaseVM vm, UnicornPointer va_list) {
        this.vm = vm;
        this.va_list = va_list;
    }

    public <T extends DvmObject> T getObject(int offset) {
        UnicornPointer pointer = va_list.getPointer(offset);
        if (pointer == null) {
            return null;
        } else {
            return vm.getObject(pointer.toUIntPeer());
        }
    }

    public int getInt(int offset) {
        return va_list.getInt(offset);
    }

    public long getLong(int offset) {
        return va_list.getLong(offset);
    }

}
