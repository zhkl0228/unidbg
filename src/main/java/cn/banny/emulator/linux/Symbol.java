package cn.banny.emulator.linux;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import net.fornwall.jelf.ElfSymbol;

public class Symbol {

    private final Module module;
    final ElfSymbol elfSymbol;

    Symbol(Module module, ElfSymbol elfSymbol) {
        this.module = module;
        this.elfSymbol = elfSymbol;
    }

    public Number[] call(Emulator emulator, Object... args) {
        return module.callFunction(emulator, elfSymbol.value, args);
    }

    public long getAddress() {
        return module.base + elfSymbol.value;
    }

    public Pointer createPointer(Emulator emulator) {
        return UnicornPointer.pointer(emulator, getAddress());
    }

}
