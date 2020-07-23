package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.SimpleARMUnwinder;
import net.fornwall.jelf.ArmExIdx;
import unicorn.ArmConst;

class AndroidARMUnwinder extends SimpleARMUnwinder {

    private long[] context;

    @Override
    protected Frame unw_step(Emulator<?> emulator, Frame frame) {
        UnicornPointer ip = frame == null ? UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_PC) : frame.ip;
        UnicornPointer sp = frame == null ? UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP) : frame.fp;
        LinuxModule module = (LinuxModule) emulator.getMemory().findModuleByAddress(ip.peer);
        ArmExIdx armExIdx = module == null ? null : module.armExIdx;
        if (armExIdx != null) {
            if (context == null) {
                context = new long[16];
                for (int i = ArmConst.UC_ARM_REG_R0; i <= ArmConst.UC_ARM_REG_R12; i++) {
                    UnicornPointer pointer = UnicornPointer.register(emulator, i);
                    context[i-ArmConst.UC_ARM_REG_R0] = pointer == null ? 0 : pointer.peer;
                }
                context[13] = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R13).peer;
                context[14] = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R14).peer;
                context[15] = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R15).peer;
            }

            long fun = ip.peer - module.base;
            return armExIdx.unwind(emulator, this, module, fun, context);
        }

        return super.unw_step(emulator, frame);
    }

}
