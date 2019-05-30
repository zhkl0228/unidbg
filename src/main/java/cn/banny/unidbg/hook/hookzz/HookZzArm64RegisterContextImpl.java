package cn.banny.unidbg.hook.hookzz;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;

import java.util.Map;

public class HookZzArm64RegisterContextImpl extends HookZzRegisterContext implements HookZzArm64RegisterContext {

    private final Pointer reg_ctx;
    private final Emulator emulator;

    HookZzArm64RegisterContextImpl(Emulator emulator, final Map<String, Object> context) {
        super(context);
        this.reg_ctx = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0).share(8); // skip dummy
        this.emulator = emulator;
    }

    @Override
    public UnicornPointer getPointerArg(int index) {
        if (index < 8) {
            return getXPointer(index);
        }

        UnicornPointer sp = getStackPointer();
        return sp.getPointer((index - 8) * emulator.getPointerSize());
    }

    @Override
    public long getXLong(int index) {
        if (index >= 0 && index <= 28) {
            return reg_ctx.getLong(index * 8);
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
        return reg_ctx.getLong(29 * 8);
    }

    @Override
    public UnicornPointer getFpPointer() {
        return UnicornPointer.pointer(emulator, getFp());
    }

    @Override
    public long getLR() {
        return reg_ctx.getLong(30 * 8);
    }

    @Override
    public UnicornPointer getLRPointer() {
        return UnicornPointer.pointer(emulator, getLR());
    }

    @Override
    public UnicornPointer getStackPointer() {
        return (UnicornPointer) reg_ctx.share(30 * 8 + 8 + 16 * 8);
    }
}
