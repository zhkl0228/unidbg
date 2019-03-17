package cn.banny.emulator.hook.hookzz;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;

import java.util.Map;

public class Arm64RegisterContextImpl extends RegisterContextImpl implements Arm64RegisterContext {

    private final Pointer reg_ctx;
    private final Emulator emulator;

    Arm64RegisterContextImpl(Emulator emulator, final Map<String, Object> context) {
        super(context);
        this.reg_ctx = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0).share(8); // skip dummy
        this.emulator = emulator;
    }

    @Override
    public long getX(int index) {
        if (index >= 0 && index <= 28) {
            return reg_ctx.getLong(index * 8);
        }
        throw new IllegalArgumentException("invalid index: " + index);
    }

    @Override
    public Pointer getXPointer(int index) {
        return UnicornPointer.pointer(emulator, getX(index));
    }

    @Override
    public long getFp() {
        return reg_ctx.getLong(29 * 8);
    }

    @Override
    public Pointer getFpPointer() {
        return UnicornPointer.pointer(emulator, getFp());
    }

    @Override
    public long getLr() {
        return reg_ctx.getLong(30 * 8);
    }

    @Override
    public Pointer getLrPointer() {
        return UnicornPointer.pointer(emulator, getLr());
    }
}
