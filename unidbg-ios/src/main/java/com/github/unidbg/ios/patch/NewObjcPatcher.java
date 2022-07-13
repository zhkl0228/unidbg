package com.github.unidbg.ios.patch;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.ModulePatcher;
import com.sun.jna.Pointer;

public class NewObjcPatcher extends ModulePatcher {

    public NewObjcPatcher() {
        super("/usr/lib/libobjc.A.dylib");
    }

    @Override
    protected void patch32(Emulator<?> emulator, Module module) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void patch64(Emulator<?> emulator, Module module) {
        {
            Pointer pointer = UnidbgPointer.pointer(emulator, module.base + 0x9f8c); // dataSegmentsContain
            assert pointer != null;
            int code = pointer.getInt(0);
            if (code != 0xd100c3ff) {
                throw new IllegalStateException("code=0x" + Integer.toHexString(code));
            }
            pointer.setInt(0, 0x52800020); // movz w0, #0x1
        }
        {
            Pointer pointer = UnidbgPointer.pointer(emulator, module.base + 0x9f90); // dataSegmentsContain
            assert pointer != null;
            int code = pointer.getInt(0);
            if (code != 0xa9014ff4) {
                throw new IllegalStateException("code=0x" + Integer.toHexString(code));
            }
            pointer.setInt(0, 0xd65f03c0); // ret
        }
    }

}
