package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.PointerNumber;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.InitFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

class MachOModuleInit extends InitFunction {

    private static final Logger log = LoggerFactory.getLogger(MachOModuleInit.class);

    private final UnidbgPointer envp;
    private final UnidbgPointer apple;
    private final UnidbgPointer vars;
    private final boolean isModInit;

    MachOModuleInit(MachOModule module, UnidbgPointer envp, UnidbgPointer apple, UnidbgPointer vars, boolean isModInit, long address) {
        super(module.base, module.name, address);
        this.envp = envp;
        this.apple = apple;
        this.vars = vars;
        this.isModInit = isModInit;
    }

    @Override
    public long getAddress() {
        return load_base + address;
    }

    /**
     * initializer(int argc, const char* argv[], const char* envp[], const char* apple[], const struct ProgramVars* vars)
     */
    public long call(Emulator<?> emulator) {
        if (isModInit) {
            log.debug("[{}]CallInitFunction: 0x{}", libName, Long.toHexString(address));
        } else {
            log.debug("[{}]CallRoutineFunction: 0x{}", libName, Long.toHexString(address));
        }
        long start = System.currentTimeMillis();
        callModInit(emulator, load_base + address, 0, null, envp, apple, vars);
        if (log.isDebugEnabled()) {
            if (isModInit) {
                System.err.println("[" + libName + "]CallInitFunction: 0x" + Long.toHexString(address) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
            } else {
                System.err.println("[" + libName + "]CallRoutineFunction: 0x" + Long.toHexString(address) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
            }
        }
        return load_base + address;
    }

    // (int argc, const char* argv[], const char* envp[], const char* apple[], const struct ProgramVars* vars)
    static void callModInit(Emulator<?> emulator, long address, int argc, UnidbgPointer argv, UnidbgPointer envp, UnidbgPointer apple, UnidbgPointer vars) {
        List<Number> list = new ArrayList<>(5);
        list.add(argc);
        list.add(argv == null ? null : new PointerNumber(UnidbgPointer.pointer(emulator, argv.peer)));
        list.add(envp == null ? null : new PointerNumber(UnidbgPointer.pointer(emulator, envp.peer)));
        list.add(apple == null ? null : new PointerNumber(UnidbgPointer.pointer(emulator, apple.peer)));
        list.add(vars == null ? null : new PointerNumber(UnidbgPointer.pointer(emulator, vars.peer)));
        emulator.eFunc(address, list.toArray(new Number[0]));
    }

}
