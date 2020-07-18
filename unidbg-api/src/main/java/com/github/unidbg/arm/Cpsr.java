package com.github.unidbg.arm;

import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;

public class Cpsr {

    private static boolean hasBit(int value, int offset) {
        return ((value >> offset) & 1) == 1;
    }

    private void setBit(int offset) {
        int mask = 1 << offset;
        value |= mask;
        unicorn.reg_write(regId, value);
    }

    private void clearBit(int offset) {
        int mask = ~(1 << offset);
        value &= mask;
        unicorn.reg_write(regId, value);
    }

    public static Cpsr getArm(Unicorn unicorn) {
        return new Cpsr(unicorn, ArmConst.UC_ARM_REG_CPSR);
    }

    public static Cpsr getArm64(Unicorn unicorn) {
        return new Cpsr(unicorn, Arm64Const.UC_ARM64_REG_NZCV);
    }

    private final Unicorn unicorn;
    private final int regId;
    private int value;

    private Cpsr(Unicorn unicorn, int regId) {
        this.unicorn = unicorn;
        this.regId = regId;
        this.value = ((Number) unicorn.reg_read(regId)).intValue();
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

    void switchUserMode() {
        value &= ~MODE_MASK;
        value |= ARMEmulator.USR_MODE;
        unicorn.reg_write(regId, value);
    }

}
