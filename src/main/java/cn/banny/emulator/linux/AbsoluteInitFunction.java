package cn.banny.emulator.linux;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.InitFunction;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class AbsoluteInitFunction extends InitFunction {

    private static final Log log = LogFactory.getLog(AbsoluteInitFunction.class);

    AbsoluteInitFunction(long load_base, String libName, long... addresses) {
        super(load_base, libName, addresses);
    }

    @Override
    public void call(Emulator emulator) {
        for (long addr : addresses) {
            Pointer pointer = UnicornPointer.pointer(emulator, addr);
            log.debug("[" + libName + "]CallInitFunction: " + pointer);
            long start = System.currentTimeMillis();
            emulator.eInit(addr);
            if (log.isDebugEnabled()) {
                System.err.println("[" + libName + "]CallInitFunction: " + pointer + ", offset=" + (System.currentTimeMillis() - start) + "ms");
            }
        }
    }

}
