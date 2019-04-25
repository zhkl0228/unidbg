package cn.banny.emulator.linux;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.spi.InitFunction;
import net.fornwall.jelf.ElfInitArray;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class LinuxInitFunction extends InitFunction {

    private static final Log log = LogFactory.getLog(LinuxInitFunction.class);

    LinuxInitFunction(long load_base, String soName, ElfInitArray initArray) {
        this(load_base, soName, initArray.array);
    }

    LinuxInitFunction(long load_base, String soName, long...addresses) {
        super(load_base, soName, addresses);
    }

    @Override
    public void call(Emulator emulator) {
        for (long addr : addresses) {
            if (addr == 0) {
                continue;
            }
            if (addr == -1) {
                continue;
            }

            log.debug("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(addr));
            long start = System.currentTimeMillis();
            emulator.eInit(load_base + addr);
            if (log.isDebugEnabled()) {
                System.err.println("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(addr) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
            }
        }
    }

}
