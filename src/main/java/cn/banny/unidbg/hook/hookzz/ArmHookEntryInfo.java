package cn.banny.unidbg.hook.hookzz;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import unicorn.ArmConst;

public class ArmHookEntryInfo implements HookEntryInfo {

    private final Pointer info;

    ArmHookEntryInfo(Emulator emulator) {
        info = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
    }

    @Override
    public long getHookId() {
        return info.getInt(0) & 0xffffffffL;
    }

    @Override
    public long getAddress() {
        return info.getInt(4) & 0xffffffffL;
    }
}
