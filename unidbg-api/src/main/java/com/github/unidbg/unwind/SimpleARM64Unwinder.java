package com.github.unidbg.unwind;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.AbstractARM64Emulator;
import com.github.unidbg.arm.AbstractARMDebugger;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import unicorn.Arm64Const;

public class SimpleARM64Unwinder implements Unwinder {

    @Override
    public void unwind(Emulator<?> emulator, AbstractARMDebugger debugger) {
        Memory memory = emulator.getMemory();
        String maxLengthSoName = memory.getMaxLengthLibraryName();
        boolean hasTrace = false;
        UnicornPointer lr = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR);
        UnicornPointer fp = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_FP);
        do {
            Module module = null;
            if (lr != null) {
                module = debugger.findModuleByAddress(lr.peer);
                if (lr.peer == AbstractARM64Emulator.LR) {
                    break;
                }
            }

            hasTrace = true;
            StringBuilder sb = new StringBuilder();
            if (module != null) {
                sb.append(String.format("[0x%09x]", module.base));
                sb.append(String.format("[%" + maxLengthSoName.length() + "s]", module.name));
                sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", lr.peer - 4 - module.base));
            } else {
                sb.append(String.format("[0x%09x]", 0L));
                sb.append(String.format("[%" + maxLengthSoName.length() + "s]", "0x" + Long.toHexString(lr == null ? 0 : lr.peer - 4)));
                if (lr != null) {
                    sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", lr.peer - 4 - 0xfffe0000L));
                }
            }
            System.out.println(sb);

            if (fp == null) {
                System.err.println("fp=null");
                break;
            }

            lr = fp.getPointer(8);
            fp = fp.getPointer(0);
        } while(true);
        if (!hasTrace) {
            System.err.println("Decode back trace failed.");
        }
    }

}
