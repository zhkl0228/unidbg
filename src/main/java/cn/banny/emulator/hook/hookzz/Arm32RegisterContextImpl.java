package cn.banny.emulator.hook.hookzz;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import unicorn.ArmConst;

import java.util.Map;

public class Arm32RegisterContextImpl extends RegisterContextImpl implements RegisterContext, Arm32RegisterContext {

    private final Pointer reg_ctx;
    private final Emulator emulator;

    Arm32RegisterContextImpl(Emulator emulator, final Map<String, Object> context) {
        super(context);
        this.reg_ctx = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0).share(8); // skip dummy
        this.emulator = emulator;
    }

    @Override
    public long getR0() {
        return reg_ctx.getInt(0) & 0xffffffffL;
    }

    @Override
    public long getR1() {
        return reg_ctx.getInt(4) & 0xffffffffL;
    }

    @Override
    public long getR2() {
        return reg_ctx.getInt(8) & 0xffffffffL;
    }

    @Override
    public long getR3() {
        return reg_ctx.getInt(12) & 0xffffffffL;
    }

    @Override
    public long getR4() {
        return reg_ctx.getInt(16) & 0xffffffffL;
    }

    @Override
    public long getR5() {
        return reg_ctx.getInt(20) & 0xffffffffL;
    }

    @Override
    public long getR6() {
        return reg_ctx.getInt(24) & 0xffffffffL;
    }

    @Override
    public long getR7() {
        return reg_ctx.getInt(28) & 0xffffffffL;
    }

    @Override
    public long getR8() {
        return reg_ctx.getInt(32) & 0xffffffffL;
    }

    @Override
    public long getR9() {
        return reg_ctx.getInt(36) & 0xffffffffL;
    }

    @Override
    public long getR10() {
        return reg_ctx.getInt(40) & 0xffffffffL;
    }

    @Override
    public long getR11() {
        return reg_ctx.getInt(44) & 0xffffffffL;
    }

    @Override
    public long getR12() {
        return reg_ctx.getInt(48) & 0xffffffffL;
    }

    @Override
    public long getLr() {
        return reg_ctx.getInt(52) & 0xffffffffL;
    }

    @Override
    public Pointer getR0Pointer() {
        return UnicornPointer.pointer(emulator, getR0());
    }

    @Override
    public Pointer getR1Pointer() {
        return UnicornPointer.pointer(emulator, getR1());
    }

    @Override
    public Pointer getR2Pointer() {
        return UnicornPointer.pointer(emulator, getR2());
    }

    @Override
    public Pointer getR3Pointer() {
        return UnicornPointer.pointer(emulator, getR3());
    }

    @Override
    public Pointer getR4Pointer() {
        return UnicornPointer.pointer(emulator, getR4());
    }

    @Override
    public Pointer getR5Pointer() {
        return UnicornPointer.pointer(emulator, getR5());
    }

    @Override
    public Pointer getR6Pointer() {
        return UnicornPointer.pointer(emulator, getR6());
    }

    @Override
    public Pointer getR7Pointer() {
        return UnicornPointer.pointer(emulator, getR7());
    }

    @Override
    public Pointer getR8Pointer() {
        return UnicornPointer.pointer(emulator, getR8());
    }

    @Override
    public Pointer getR9Pointer() {
        return UnicornPointer.pointer(emulator, getR9());
    }

    @Override
    public Pointer getR10Pointer() {
        return UnicornPointer.pointer(emulator, getR10());
    }

    @Override
    public Pointer getR11Pointer() {
        return UnicornPointer.pointer(emulator, getR11());
    }

    @Override
    public Pointer getR12Pointer() {
        return UnicornPointer.pointer(emulator, getR12());
    }

    @Override
    public Pointer getLrPointer() {
        return UnicornPointer.pointer(emulator, getLr());
    }
}
