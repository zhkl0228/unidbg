package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.InitFunction;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class AbsoluteInitFunction extends InitFunction {

    private static final Log log = LogFactory.getLog(AbsoluteInitFunction.class);

    AbsoluteInitFunction(long load_base, String libName, long address) {
        super(load_base, libName, address);
    }

    @Override
    public long getAddress() {
        return address;
    }

    @Override
    public void call(Emulator<?> emulator) {
        long address = this.address;
        if (!emulator.is64Bit()) {
            address = (int) address;
        }

        if (address == 0 || address == -1) {
            return;
        }

        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        log.debug("[" + libName + "]CallInitFunction: " + pointer);
        long start = System.currentTimeMillis();

        emulator.eInit(address);
        if (AbsoluteInitFunction.log.isDebugEnabled()) {
            System.err.println("[" + libName + "]CallInitFunction: " + pointer + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
    }

}
