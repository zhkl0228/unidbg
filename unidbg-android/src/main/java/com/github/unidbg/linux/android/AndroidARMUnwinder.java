package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.SimpleARMUnwinder;
import net.fornwall.jelf.ArmExIdx;
import net.fornwall.jelf.DwarfCursor;
import net.fornwall.jelf.DwarfCursor32;
import net.fornwall.jelf.GnuEhFrameHeader;
import net.fornwall.jelf.MemoizedObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

class AndroidARMUnwinder extends SimpleARMUnwinder {

    private static final Logger log = LoggerFactory.getLogger(AndroidARMUnwinder.class);

    private final DwarfCursor context;

    public AndroidARMUnwinder(Emulator<?> emulator) {
        super(emulator);
        this.context = new DwarfCursor32(emulator);
    }

    @Override
    protected Frame unw_step(Emulator<?> emulator, Frame frame) {
        try {
            LinuxModule module = (LinuxModule) emulator.getMemory().findModuleByAddress(this.context.ip);
            MemoizedObject<GnuEhFrameHeader> ehFrameHeader = module == null ? null : module.ehFrameHeader;
            if (ehFrameHeader != null) {
                long fun = this.context.ip - module.base;
                GnuEhFrameHeader frameHeader = ehFrameHeader.getValue();
                Frame ret = frameHeader == null ? null : frameHeader.dwarf_step(emulator, this, module, fun, context);
                if (ret != null) {
                    return ret;
                }
            }
            MemoizedObject<ArmExIdx> armExIdx = module == null ? null : module.armExIdx;
            if (armExIdx != null) {
                long fun = this.context.ip - module.base;
                return armExIdx.getValue().arm_exidx_step(emulator, this, module, fun, context);
            }
        } catch (RuntimeException exception) {
            log.warn("unw_step", exception);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return super.unw_step(emulator, frame);
    }

}
