package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.spi.InitFunction;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class LinuxInitFunction extends InitFunction {

    private static final Log log = LogFactory.getLog(LinuxInitFunction.class);

    LinuxInitFunction(long load_base, String soName, long address) {
        super(load_base, soName, address);
    }

    @Override
    public long getAddress() {
        return load_base + address;
    }

    @Override
    public void call(Emulator<?> emulator) {
        if (address == 0 || address == -1) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(address));
        }
        long start = System.currentTimeMillis();
        emulator.eInit(getAddress());
        if (log.isDebugEnabled()) {
            System.err.println("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(address) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
    }

}
