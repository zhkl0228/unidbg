package cn.banny.unidbg.linux;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.linux.android.dvm.VM;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.utils.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.HashMap;
import java.util.Map;

public abstract class VirtualModule {

    private static final Log log = LogFactory.getLog(VirtualModule.class);

    private final String name;
    private final Map<String, UnicornPointer> symbols = new HashMap<>();

    protected VirtualModule(Emulator emulator, VM vm, String name) {
        this.name = name;

        onInitialize(emulator, vm, symbols);
    }

    protected abstract void onInitialize(Emulator emulator, VM vm, Map<String, UnicornPointer> symbols);

    public Module register(Memory memory) {
        if (StringUtils.isEmpty(name)) {
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
