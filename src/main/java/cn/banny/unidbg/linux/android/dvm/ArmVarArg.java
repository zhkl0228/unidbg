package cn.banny.unidbg.linux.android.dvm;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class ArmVarArg implements VarArg {

    static VarArg armVarArg(Emulator emulator, BaseVM vm, int regOffset) {
        return new ArmVarArg(emulator, vm, ArmConst.UC_ARM_REG_R0, 4, ArmConst.UC_ARM_REG_SP, regOffset, 4);
    }

    static VarArg arm64VarArg(Emulator emulator, BaseVM vm, int regOffset) {
        return new ArmVarArg(emulator, vm, Arm64Const.UC_ARM64_REG_X0, 8, Arm64Const.UC_ARM64_REG_SP, regOffset, 8);
    }

    private final Emulator emulator;
    private final BaseVM vm;
    private final int firstArgReg;
    private final int regArgCount;
    private final int spReg;
    private final int regOffset;
    private final int pointerSize;

    private ArmVarArg(Emulator emulator, BaseVM vm, int firstArgReg, int regArgCount, int spReg, int regOffset, int pointerSize) {
        this.emulator = emulator;
        this.vm = vm;
        this.firstArgReg = firstArgReg;
        this.regArgCount = regArgCount;
        this.spReg = spReg;
        this.regOffset = regOffset;
        this.pointerSize = pointerSize;
    }

    @Override
    public <T extends DvmObject> T getObject(int index) {
        return vm.getObject(getArg(index).toUIntPeer());
    }

    @Override
    public int getInt(int index) {
        return (int) getArg(index).peer;
    }

    private UnicornPointer getArg(int index) {
        int offset = regOffset + index;
        if (offset < regArgCount) {
            int reg = firstArgReg + offset;
            return UnicornPointer.register(emulator, reg);
        }

        UnicornPointer sp = UnicornPointer.register(emulator, spReg);
        return sp.getPointer((offset - regArgCount) * pointerSize);
    }

}
