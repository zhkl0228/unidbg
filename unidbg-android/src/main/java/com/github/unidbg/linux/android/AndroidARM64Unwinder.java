package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.SimpleARM64Unwinder;
import net.fornwall.jelf.ArmExIdx;
import net.fornwall.jelf.DwarfCursor;
import net.fornwall.jelf.DwarfCursor64;
import net.fornwall.jelf.GnuEhFrameHeader;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class AndroidARM64Unwinder extends SimpleARM64Unwinder {

    private final DwarfCursor context;

    public AndroidARM64Unwinder(Emulator<?> emulator) {
        super(emulator);
        this.context = new DwarfCursor64(emulator);
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
