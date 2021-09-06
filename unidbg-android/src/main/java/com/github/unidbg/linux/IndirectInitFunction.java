package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class IndirectInitFunction extends AbsoluteInitFunction {

    private static final Log log = LogFactory.getLog(IndirectInitFunction.class);

    private final UnidbgPointer func;

    public IndirectInitFunction(long load_base, String libName, UnidbgPointer func) {
        super(load_base, libName, 0);

        this.func = func;
    }

    @Override
    public void call(Emulator<?> emulator) {
        UnidbgPointer ptr = func.getPointer(0);
        if (ptr == null) {
            return;
        }
        long address = ptr.peer;
        if (!emulator.is64Bit()) {
            address = (int) address;
        }

        if (address == 0 || address == -1) {
            return;
        }

        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        if (log.isDebugEnabled()) {
            log.debug("[" + libName + "]CallInitFunction: " + pointer);
        }
        long start = System.currentTimeMillis();

        emulator.eInit(address);
        if (log.isDebugEnabled()) {
            System.err.println("[" + libName + "]CallInitFunction: " + pointer + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
    }

}
