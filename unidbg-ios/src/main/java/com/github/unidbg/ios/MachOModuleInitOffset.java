package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.InitFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class MachOModuleInitOffset extends InitFunction {

    private static final Logger log = LoggerFactory.getLogger(MachOModuleInitOffset.class);

    private final UnidbgPointer envp;
    private final UnidbgPointer apple;
    private final UnidbgPointer vars;

    MachOModuleInitOffset(MachOModule module, UnidbgPointer envp, UnidbgPointer apple, UnidbgPointer vars, long address) {
        super(module.base, module.name, address);
        this.envp = envp;
        this.apple = apple;
        this.vars = vars;
    }

    @Override
    public long getAddress() {
        return address;
    }

    /**
     * initializer(int argc, const char* argv[], const char* envp[], const char* apple[], const struct ProgramVars* vars)
     */
    public long call(Emulator<?> emulator) {
        log.debug("[{}]CallInitOffsetFunction: 0x{}", libName, Long.toHexString(address));
        long start = System.currentTimeMillis();
        MachOModuleInit.callModInit(emulator, address, 0, null, envp, apple, vars);
        if (log.isDebugEnabled()) {
            System.err.println("[" + libName + "]CallInitOffsetFunction: 0x" + Long.toHexString(address) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        return address;
    }

}
