package com.github.unidbg.arm.context;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import unicorn.ArmConst;

public class BackendArm32RegisterContext extends BaseRegisterContext implements EditableArm32RegisterContext {

    private final Backend backend;

    public BackendArm32RegisterContext(Backend backend, Emulator<?> emulator) {
        super(emulator, ArmConst.UC_ARM_REG_R0, 4);
        this.backend = backend;
    }

    private long reg(int regId) {
        return backend.reg_read(regId).intValue() & 0xffffffffL;
    }

    private void set(int regId, int value) {
        backend.reg_write(regId, value);
    }

    @Override
    public long getR0Long() {
        return reg(ArmConst.UC_ARM_REG_R0);
    }

    @Override
    public long getR1Long() {
        return reg(ArmConst.UC_ARM_REG_R1);
    }

    @Override
    public long getR2Long() {
        return reg(ArmConst.UC_ARM_REG_R2);
    }

    @Override
    public long getR3Long() {
        return reg(ArmConst.UC_ARM_REG_R3);
    }

    @Override
    public long getR4Long() {
        return reg(ArmConst.UC_ARM_REG_R4);
    }

    @Override
    public long getR5Long() {
        return reg(ArmConst.UC_ARM_REG_R5);
    }

    @Override
    public long getR6Long() {
        return reg(ArmConst.UC_ARM_REG_R6);
    }

    @Override
    public long getR7Long() {
        return reg(ArmConst.UC_ARM_REG_R7);
    }

    @Override
    public long getR8Long() {
        return reg(ArmConst.UC_ARM_REG_R8);
    }

    @Override
    public long getR9Long() {
        return reg(ArmConst.UC_ARM_REG_R9);
    }

    @Override
    public long getR10Long() {
        return reg(ArmConst.UC_ARM_REG_R10);
    }

    @Override
    public long getR11Long() {
        return reg(ArmConst.UC_ARM_REG_R11);
    }

    @Override
    public long getR12Long() {
        return reg(ArmConst.UC_ARM_REG_R12);
    }

    @Override
    public void setR0(int r0) {
        set(ArmConst.UC_ARM_REG_R0, r0);
    }

    @Override
    public void setR1(int r1) {
        set(ArmConst.UC_ARM_REG_R1, r1);
    }

    @Override
    public void setR2(int r2) {
        set(ArmConst.UC_ARM_REG_R2, r2);
    }

    @Override
    public void setR3(int r3) {
        set(ArmConst.UC_ARM_REG_R3, r3);
    }

    @Override
    public void setR4(int r4) {
        set(ArmConst.UC_ARM_REG_R4, r4);
    }

    @Override
    public void setR5(int r5) {
        set(ArmConst.UC_ARM_REG_R5, r5);
    }

    @Override
    public void setR6(int r6) {
        set(ArmConst.UC_ARM_REG_R6, r6);
    }

    @Override
    public void setR7(int r7) {
        set(ArmConst.UC_ARM_REG_R7, r7);
    }

    @Override
    public int getR0Int() {
        return (int) getR0Long();
    }

    @Override
    public int getR1Int() {
        return (int) getR1Long();
    }

    @Override
    public int getR2Int() {
        return (int) getR2Long();
    }

    @Override
    public int getR3Int() {
        return (int) getR3Long();
    }

    @Override
    public int getR4Int() {
        return (int) getR4Long();
    }

    @Override
    public int getR5Int() {
        return (int) getR5Long();
    }

    @Override
    public int getR6Int() {
        return (int) getR6Long();
    }

    @Override
    public int getR7Int() {
        return (int) getR7Long();
    }

    @Override
    public int getR8Int() {
        return (int) getR8Long();
    }

    @Override
    public int getR9Int() {
        return (int) getR9Long();
    }

    @Override
    public int getR10Int() {
        return (int) getR10Long();
    }

    @Override
    public int getR11Int() {
        return (int) getR11Long();
    }

    @Override
    public int getR12Int() {
        return (int) getR12Long();
    }

    @Override
    public UnidbgPointer getR0Pointer() {
        return UnidbgPointer.pointer(emulator, getR0Long());
    }

    @Override
    public UnidbgPointer getR1Pointer() {
        return UnidbgPointer.pointer(emulator, getR1Long());
    }

    @Override
    public UnidbgPointer getR2Pointer() {
        return UnidbgPointer.pointer(emulator, getR2Long());
    }

    @Override
    public UnidbgPointer getR3Pointer() {
        return UnidbgPointer.pointer(emulator, getR3Long());
    }

    @Override
    public UnidbgPointer getR4Pointer() {
        return UnidbgPointer.pointer(emulator, getR4Long());
    }

    @Override
    public UnidbgPointer getR5Pointer() {
        return UnidbgPointer.pointer(emulator, getR5Long());
    }

    @Override
    public UnidbgPointer getR6Pointer() {
        return UnidbgPointer.pointer(emulator, getR6Long());
    }

    @Override
    public UnidbgPointer getR7Pointer() {
        return UnidbgPointer.pointer(emulator, getR7Long());
    }

    @Override
    public UnidbgPointer getR8Pointer() {
        return UnidbgPointer.pointer(emulator, getR8Long());
    }

    @Override
    public UnidbgPointer getR9Pointer() {
        return UnidbgPointer.pointer(emulator, getR9Long());
    }

    @Override
    public UnidbgPointer getR10Pointer() {
        return UnidbgPointer.pointer(emulator, getR10Long());
    }

    @Override
    public UnidbgPointer getR11Pointer() {
        return UnidbgPointer.pointer(emulator, getR11Long());
    }

    @Override
    public UnidbgPointer getR12Pointer() {
        return UnidbgPointer.pointer(emulator, getR12Long());
    }

    @Override
    public UnidbgPointer getLRPointer() {
        return UnidbgPointer.pointer(emulator, getLR());
    }

    @Override
    public UnidbgPointer getPCPointer() {
        return UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
    }

    @Override
    public long getLR() {
        return reg(ArmConst.UC_ARM_REG_LR);
    }

    @Override
    public UnidbgPointer getStackPointer() {
        return UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
    }

    @Override
    public void setStackPointer(Pointer sp) {
        backend.reg_write(ArmConst.UC_ARM_REG_SP, ((UnidbgPointer) sp).peer);
    }
}
