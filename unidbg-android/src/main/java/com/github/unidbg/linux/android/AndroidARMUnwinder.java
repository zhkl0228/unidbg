package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.SimpleARMUnwinder;
import net.fornwall.jelf.ArmExIdx;
import net.fornwall.jelf.DwarfCursor;
import net.fornwall.jelf.GnuEhFrameHeader;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class AndroidARMUnwinder extends SimpleARMUnwinder {

    private final DwarfCursor context;

    public AndroidARMUnwinder(Emulator<?> emulator) {
        super(emulator);
        this.context = new DwarfCursor(emulator);
    }

    @Override
    protected Frame unw_step(Emulator<?> emulator, Frame frame) {
        try {
            LinuxModule module = (LinuxModule) emulator.getMemory().findModuleByAddress(this.context.ip);
            GnuEhFrameHeader ehFrameHeader = module == null ? null : module.ehFrameHeader;
            if (ehFrameHeader != null) {
                long fun = this.context.ip - module.base;
                Frame ret = ehFrameHeader.dwarf_step(emulator, this, module, fun, context);
                if (ret != null) {
                    return ret;
                }
            }
            ArmExIdx armExIdx = module == null ? null : module.armExIdx;
            if (armExIdx != null) {
                long fun = this.context.ip - module.base;
                return armExIdx.arm_exidx_step(emulator, this, module, fun, context);
            }
        } catch (RuntimeException exception) {
            Log log = LogFactory.getLog(GnuEhFrameHeader.class);
            if (!log.isDebugEnabled()) {
                log = LogFactory.getLog(ArmExIdx.class);
            }
            if (log.isDebugEnabled()) {
                throw exception;
            }
        }

        return super.unw_step(emulator, frame);
    }

}
