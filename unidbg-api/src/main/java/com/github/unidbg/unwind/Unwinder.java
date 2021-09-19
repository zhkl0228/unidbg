package com.github.unidbg.unwind;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.AbstractARMDebugger;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.zhkl0228.demumble.DemanglerFactory;
import com.github.zhkl0228.demumble.GccDemangler;

public abstract class Unwinder {

    public static final int SYMBOL_SIZE = 0x1000;

    protected final Emulator<?> emulator;

    protected Unwinder(Emulator<?> emulator) {
        this.emulator = emulator;
    }

    public abstract Frame createFrame(UnidbgPointer ip, UnidbgPointer fp);

    protected abstract Frame unw_step(Emulator<?> emulator, Frame frame);

    protected abstract String getBaseFormat();

    public final void unwind() {
        Memory memory = emulator.getMemory();
        String maxLengthSoName = memory.getMaxLengthLibraryName();
        boolean hasTrace = false;

        Frame frame = null;
        while((frame = unw_step(emulator, frame)) != null) {
            if (frame.isFinish()) {
                if (!hasTrace) {
                    System.out.println("Decode backtrace finish");
                }
                return;
            }

            hasTrace = true;
            printFrameElement(maxLengthSoName, memory, frame.ip);
        }

        if (!hasTrace) {
            System.err.println("Decode backtrace failed.");
        }
    }

    private void printFrameElement(String maxLengthSoName, Memory memory, UnidbgPointer ip) {
        Module module = AbstractARMDebugger.findModuleByAddress(emulator, ip.peer);
        StringBuilder sb = new StringBuilder();
        String format = getBaseFormat();
        if (module != null) {
            sb.append(String.format(format, module.base)).append(String.format(format, ip.peer));
            sb.append(String.format("[%" + maxLengthSoName.length() + "s]", module.name));
            sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", ip.peer - module.base));

            Symbol symbol = module.findClosestSymbolByAddress(ip.peer, false);
            if (symbol != null && ip.peer - symbol.getAddress() <= SYMBOL_SIZE) {
                GccDemangler demangler = DemanglerFactory.createDemangler();
                sb.append(" ").append(demangler.demangle(symbol.getName())).append(" + 0x").append(Long.toHexString(ip.peer - symbol.getAddress()));
            }
        } else {
            sb.append(String.format(format, 0)).append(String.format(format, ip.peer));
            sb.append(String.format("[%" + maxLengthSoName.length() + "s]", "0x" + Long.toHexString(ip.peer)));
            if (ip.peer >= 0xfffe0000L) {
                sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", ip.peer - 0xfffe0000L));
            }
        }
        System.out.println(sb);
    }

}
