package cn.banny.unidbg.linux.android.dvm;

import cn.banny.unidbg.pointer.UnicornPointer;

public class VaList32 extends VaList {

    private final BaseVM vm;
    private final UnicornPointer va_list;

    VaList32(BaseVM vm, UnicornPointer va_list, DvmMethod method) {
        super(method);
        this.vm = vm;
        this.va_list = va_list;
    }

    @Override
    public <T extends DvmObject<?>> T getObject(int offset) {
        UnicornPointer pointer = va_list.getPointer(offset);
        if (pointer == null) {
            return null;
        } else {
            return vm.getObject(pointer.toUIntPeer());
        }
    }

    @Override
    public int getInt(int offset) {
        return va_list.getInt(offset);
    }

    @Override
    public long getLong(int offset) {
        return va_list.getLong(offset);
    }

    @Override
    public float getFloat(int offset) {
        return va_list.getFloat(offset);
    }

    @Override
    public double getDouble(int offset) {
        return va_list.getDouble(offset);
    }
}
