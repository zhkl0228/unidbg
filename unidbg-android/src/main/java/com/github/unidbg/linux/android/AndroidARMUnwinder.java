package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.LinuxModule;
import net.fornwall.jelf.DwarfCursor;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.SimpleARMUnwinder;
import net.fornwall.jelf.ArmExIdx;

class AndroidARMUnwinder extends SimpleARMUnwinder {

    private final DwarfCursor context;

    public AndroidARMUnwinder(Emulator<?> emulator) {
        this.context = new DwarfCursor(emulator);
    }

    @Override
    protected Frame unw_step(Emulator<?> emulator, Frame frame) {
        LinuxModule module = (LinuxModule) emulator.getMemory().findModuleByAddress(this.context.ip);
        ArmExIdx armExIdx = module == null ? null : module.armExIdx;
        if (armExIdx != null) {
            long fun = this.context.ip - module.base;
            return armExIdx.unwind(emulator, this, module, fun, context);
        }

        return super.unw_step(emulator, frame);
    }

}
