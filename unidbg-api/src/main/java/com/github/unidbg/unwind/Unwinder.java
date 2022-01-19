package com.github.unidbg.unwind;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.AbstractARMDebugger;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
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
        final int maxLength = maxLengthSoName.length();
        SvcMemory svcMemory = emulator.getSvcMemory();
        MemRegion region = svcMemory.findRegion(ip.peer);
        Module module = region != null ? null : AbstractARMDebugger.findModuleByAddress(emulator, ip.peer);
        StringBuilder sb = new StringBuilder();
        String format = getBaseFormat();
        if (module != null) {
            sb.append(String.format(format, module.base)).append(String.format(format, ip.peer));
            sb.append(String.format("[%" + maxLength + "s]", module.name));
            sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", ip.peer - module.base));

            Symbol symbol = module.findClosestSymbolByAddress(ip.peer, false);
            if (symbol != null && ip.peer - symbol.getAddress() <= SYMBOL_SIZE) {
                GccDemangler demangler = DemanglerFactory.createDemangler();
                sb.append(" ").append(demangler.demangle(symbol.getName())).append(" + 0x").append(Long.toHexString(ip.peer - (symbol.getAddress() & ~1)));
            }
        } else {
            sb.append(String.format(format, 0)).append(String.format(format, ip.peer));
            if (region == null) {
                sb.append(String.format("[%" + maxLength + "s]", "0x" + Long.toHexString(ip.peer)));
            } else {
                sb.append(String.format("[%" + maxLength + "s]", region.getName().substring(0, Math.min(maxLength, region.getName().length()))));
            }
            if (ip.peer >= svcMemory.getBase()) {
                sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", ip.peer - svcMemory.getBase()));
            }
        }
        System.out.println(sb);
    }

}
