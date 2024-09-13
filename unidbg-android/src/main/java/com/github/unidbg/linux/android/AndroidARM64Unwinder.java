package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.SimpleARM64Unwinder;
import net.fornwall.jelf.DwarfCursor;
import net.fornwall.jelf.DwarfCursor64;
import net.fornwall.jelf.GnuEhFrameHeader;
import net.fornwall.jelf.MemoizedObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

class AndroidARM64Unwinder extends SimpleARM64Unwinder {

    private static final Logger log = LoggerFactory.getLogger(AndroidARM64Unwinder.class);

    private final DwarfCursor context;

    public AndroidARM64Unwinder(Emulator<?> emulator) {
        super(emulator);
        this.context = new DwarfCursor64(emulator);
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
        } catch (RuntimeException exception) {
            log.warn("unw_step", exception);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return super.unw_step(emulator, frame);
    }

}
