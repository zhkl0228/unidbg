package cn.banny.unidbg.linux.android.dvm;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;

public class ArmVarArg implements VarArg {

    static VarArg create(Emulator emulator, BaseVM vm) {
        return new ArmVarArg(emulator, vm);
    }

    private final Emulator emulator;
    private final BaseVM vm;

    private ArmVarArg(Emulator emulator, BaseVM vm) {
        this.emulator = emulator;
        this.vm = vm;
    }

    @Override
    public <T extends DvmObject> T getObject(int index) {
        return vm.getObject(getArg(index).toUIntPeer());
    }

    @Override
    public int getInt(int index) {
        UnicornPointer pointer = getArg(index);
        return pointer == null ? 0 : (int) pointer.peer;
    }

    private static final int REG_OFFSET = 3;

    private UnicornPointer getArg(int index) {
        return emulator.getContext().getPointerArg(REG_OFFSET + index);
    }

}
