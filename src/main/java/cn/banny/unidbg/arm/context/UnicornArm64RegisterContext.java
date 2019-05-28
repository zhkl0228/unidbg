package cn.banny.unidbg.arm.context;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;
import unicorn.Arm64Const;
import unicorn.Unicorn;

public class UnicornArm64RegisterContext extends BaseRegisterContext implements EditableArm64RegisterContext {

    private final Unicorn unicorn;

    public UnicornArm64RegisterContext(Unicorn unicorn, Emulator emulator) {
        super(emulator, Arm64Const.UC_ARM64_REG_X0, 8);
        this.unicorn = unicorn;
    }

    private long reg(int regId) {
        return ((Number) unicorn.reg_read(regId)).longValue();
    }

    @Override
    public void setXLong(int index, long value) {
        if (index >= 0 && index <= 28) {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_X0 + index, value);
            return;
        }
        throw new IllegalArgumentException("invalid index: " + index);
    }

    @Override
    public long getXLong(int index) {
        if (index >= 0 && index <= 28) {
            return reg(Arm64Const.UC_ARM64_REG_X0 + index);
        }
        throw new IllegalArgumentException("invalid index: " + index);
    }

    @Override
    public int getXInt(int index) {
        return (int) getXLong(index);
    }

    @Override
    public UnicornPointer getXPointer(int index) {
        return UnicornPointer.pointer(emulator, getXLong(index));
    }

    @Override
    public long getFp() {
        return reg(Arm64Const.UC_ARM64_REG_FP);
    }

    @Override
    public UnicornPointer getFpPointer() {
        return UnicornPointer.pointer(emulator, getFp());
    }

    @Override
    public long getLr() {
        return reg(Arm64Const.UC_ARM64_REG_LR);
    }

    @Override
    public UnicornPointer getLrPointer() {
        return UnicornPointer.pointer(emulator, getLr());
    }

    @Override
    public UnicornPointer getStackPointer() {
        return UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_SP);
    }
}
