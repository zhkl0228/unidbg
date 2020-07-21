package com.github.unidbg.unwind;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.AbstractARMDebugger;
import com.github.unidbg.arm.AbstractARMEmulator;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import unicorn.ArmConst;

public class SimpleARMUnwinder implements Unwinder {

    @Override
    public void unwind(Emulator<?> emulator, AbstractARMDebugger debugger) {
        Memory memory = emulator.getMemory();
        String maxLengthSoName = memory.getMaxLengthLibraryName();
        boolean hasTrace = false;
        UnicornPointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        UnicornPointer lr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
        UnicornPointer r7 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R7);
        do {
            Module module = null;
            if (lr != null) {
                module = debugger.findModuleByAddress(lr.peer);
                if (lr.peer == AbstractARMEmulator.LR) {
                    break;
                }
            }

            boolean thumb = lr != null && (lr.peer & 1) == 1;
            hasTrace = true;
            StringBuilder sb = new StringBuilder();
            if (module != null) {
                sb.append(String.format("[0x%08x]", module.base));
                sb.append(String.format("[%" + maxLengthSoName.length() + "s]", module.name));
                sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", lr.peer - (thumb ? 2 : 4) - module.base + (thumb ? 1 : 0)));
            } else {
                sb.append(String.format("[0x%08x]", 0));
                sb.append(String.format("[%" + maxLengthSoName.length() + "s]", "0x" + Long.toHexString(lr == null ? 0 : lr.peer - (thumb ? 2 : 4))));
                if (lr != null) {
                    sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", lr.peer - (thumb ? 2 : 4) - 0xfffe0000L + (thumb ? 1 : 0)));
                }
            }
            System.out.println(sb);

            if (r7 == null || r7.peer < sp.peer) {
                System.err.println("r7=" + r7 + ", sp=" + sp);
                break;
            }

            lr = r7.getPointer(4);
            r7 = r7.getPointer(0);
        } while(true);
        if (!hasTrace) {
            System.err.println("Decode back trace failed.");
        }
    }

}
