package com.github.unidbg.virtualmodule;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.HashMap;
import java.util.Map;

public abstract class VirtualModule {

    private static final Log log = LogFactory.getLog(VirtualModule.class);

    private final String name;
    private final Map<String, UnicornPointer> symbols = new HashMap<>();

    protected VirtualModule(Emulator<?> emulator, String name) {
        this(emulator, null, name);
    }

    protected VirtualModule(Emulator<?> emulator, VM vm, String name) {
        this.name = name;

        onInitialize(emulator, vm, symbols);
    }

    protected abstract void onInitialize(Emulator<?> emulator, VM vm, Map<String, UnicornPointer> symbols);

    public Module register(Memory memory) {
        if (name == null || name.trim().length() < 1) {
            throw new IllegalArgumentException("name is empty");
        }
        if (symbols.isEmpty()) {
            throw new IllegalArgumentException("symbols is empty");
        }

        if (log.isDebugEnabled()) {
            log.debug(String.format("Register virtual module[%s]: (%s)", name, symbols));
        }
        return memory.loadVirtualModule(name, symbols);
    }

}
