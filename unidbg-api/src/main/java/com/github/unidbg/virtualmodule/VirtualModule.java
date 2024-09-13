package com.github.unidbg.virtualmodule;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public abstract class VirtualModule<T> {

    private static final Logger log = LoggerFactory.getLogger(VirtualModule.class);

    private final String name;
    private final Map<String, UnidbgPointer> symbols = new HashMap<>();

    protected VirtualModule(Emulator<?> emulator, String name) {
        this(emulator, null, name);
    }

    protected VirtualModule(Emulator<?> emulator, T extra, String name) {
        this.name = name;

        onInitialize(emulator, extra, symbols);
    }

    protected abstract void onInitialize(Emulator<?> emulator, T extra, Map<String, UnidbgPointer> symbols);

    public Module register(Memory memory) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("name is empty");
        }
        if (symbols.isEmpty()) {
            throw new IllegalArgumentException("symbols is empty");
        }

        if (log.isDebugEnabled()) {
            log.debug("Register virtual module[{}]: ({})", name, symbols);
        }
        return memory.loadVirtualModule(name, symbols);
    }

}
