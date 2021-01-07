package com.github.unidbg.arm;

import com.github.unidbg.arm.backend.Backend;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class Cpsr {

    private static boolean hasBit(int value, int offset) {
        return ((value >> offset) & 1) == 1;
    }

    private void setBit(int offset) {
        int mask = 1 << offset;
        value |= mask;
        backend.reg_write(regId, value);
    }

    private void clearBit(int offset) {
        int mask = ~(1 << offset);
        value &= mask;
        backend.reg_write(regId, value);
    }

    public static Cpsr getArm(Backend backend) {
        return new Cpsr(backend, ArmConst.UC_ARM_REG_CPSR);
    }

    public static Cpsr getArm64(Backend backend) {
        return new Cpsr(backend, Arm64Const.UC_ARM64_REG_NZCV);
    }

    private final Backend backend;
    private final int regId;
    private int value;

    private Cpsr(Backend backend, int regId) {
        this.backend = backend;
        this.regId = regId;
        this.value = backend.reg_read(regId).intValue();
    }

    public int getValue() {
        return value;
    }

    private static final int A32_BIT = 4;

    boolean isA32() {
        return hasBit(value, A32_BIT);
    }

    private static final int THUMB_BIT = 5;

    boolean isThumb() {
        return hasBit(value, THUMB_BIT);
    }

    private static final int NEGATIVE_BIT = 31;

    boolean isNegative() {
        return hasBit(value, NEGATIVE_BIT);
    }

    void setNegative(boolean on) {
        if (on) {
            setBit(NEGATIVE_BIT);
        } else {
            clearBit(NEGATIVE_BIT);
        }
    }

    private static final int ZERO_BIT = 30;

    boolean isZero() {
        return hasBit(value, ZERO_BIT);
    }

    void setZero(boolean on) {
        if (on) {
            setBit(ZERO_BIT);
        } else {
            clearBit(ZERO_BIT);
        }
    }

    private static final int CARRY_BIT = 29;

    /**
     * 进位或借位
     */
    boolean hasCarry() {
        return hasBit(value, CARRY_BIT);
    }

    public void setCarry(boolean on) {
        if (on) {
            setBit(CARRY_BIT);
        } else {
            clearBit(CARRY_BIT);
        }
    }

    private static final int OVERFLOW_BIT = 28;

    boolean isOverflow() {
        return hasBit(value, OVERFLOW_BIT);
    }

    void setOverflow(boolean on) {
        if (on) {
            setBit(OVERFLOW_BIT);
        } else {
            clearBit(OVERFLOW_BIT);
        }
    }

    private static final int MODE_MASK = 0x1f;

    int getMode() {
        return value & MODE_MASK;
    }

    int getEL() {
        return (value >> 2) & 3;
    }

    public final void switchUserMode() {
        value &= ~MODE_MASK;
        value |= ARMEmulator.USR_MODE;
        backend.reg_write(regId, value);
    }

}
