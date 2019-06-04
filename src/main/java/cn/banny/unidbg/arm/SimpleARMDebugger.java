package cn.banny.unidbg.arm;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.debugger.Debugger;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.util.Scanner;

class SimpleARMDebugger extends AbstractARMDebugger implements Debugger {

    SimpleARMDebugger(Emulator emulator) {
        super(emulator);
    }

    @Override
    final void loop(Emulator emulator, Unicorn u, long address, int size) {
        System.out.println("debugger break at: 0x" + Long.toHexString(address));
        boolean thumb = ARM.isThumb(u);
        long nextAddress = 0;
        try {
            emulator.showRegs();
            nextAddress = disassemble(emulator, address, size, thumb);
        } catch (UnicornException e) {
            e.printStackTrace();
        }

        Scanner scanner = new Scanner(System.in);
        String line;
        while ((line = scanner.nextLine()) != null) {
            try {
                if ("help".equals(line)) {
                    showHelp();
                    continue;
                }
                if ("d".equals(line) || "dis".equals(line)) {
                    emulator.showRegs();
                    disassemble(emulator, address, size, thumb);
                    continue;
                }
                if (line.startsWith("m")) {
                    String command = line;
                    String[] tokens = line.split("\\s+");
                    int length = 0x70;
                    try {
                        if (tokens.length >= 2) {
                            command = tokens[0];
                            int radix = 10;
                            String str = tokens[1];
                            if (str.startsWith("0x")) {
                                str = str.substring(2);
                                radix = 16;
                            }
                            length = Integer.parseInt(str, radix);
                        }
                    } catch(NumberFormatException ignored) {}
                    boolean nullTerminated = false;
                    if (command.endsWith("s")) {
                        nullTerminated = true;
                        command = command.substring(0, command.length() - 1);
                    }

                    int reg = -1;
                    String name = null;
                    if (command.startsWith("mr") && command.length() == 3) {
                        char c = command.charAt(2);
                        if (c >= '0' && c <= '7') {
                            int r = c - '0';
                            reg = ArmConst.UC_ARM_REG_R0 + r;
                            name = "r" + r;
                        }
                    } else if ("mfp".equals(command)) {
                        reg = ArmConst.UC_ARM_REG_FP;
                        name = "fp";
                    } else if ("mip".equals(command)) {
                        reg = ArmConst.UC_ARM_REG_IP;
                        name = "ip";
                    } else if ("msp".equals(command)) {
                        reg = ArmConst.UC_ARM_REG_SP;
                        name = "sp";
                    } else if (command.startsWith("m0x")) {
                        long addr = Long.parseLong(command.substring(3).trim(), 16);
                        Pointer pointer = UnicornPointer.pointer(emulator, addr);
                        if (pointer != null) {
                            dumpMemory(pointer, length, pointer.toString(), nullTerminated);
                        } else {
                            System.out.println(addr + " is null");
                        }
                        continue;
                    }
                    if (reg != -1) {
                        Pointer pointer = UnicornPointer.register(emulator, reg);
                        if (pointer != null) {
                            dumpMemory(pointer, length, name + "=" + pointer, nullTerminated);
                        } else {
                            System.out.println(name + " is null");
                        }
                        continue;
                    }
                }
                if ("bt".equals(line)) {
                    Memory memory = emulator.getMemory();
                    String maxLengthSoName = memory.getMaxLengthLibraryName();
                    boolean hasTrace = false;
                    UnicornPointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                    UnicornPointer lr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
                    UnicornPointer r7 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R7);
                    do {
                        Module module = null;
                        if (lr != null) {
                            module = findModuleByAddress(lr.peer);
                            if (lr.peer == AndroidARMEmulator.LR) {
                                break;
                            }
                        }

                        hasTrace = true;
                        StringBuilder sb = new StringBuilder();
                        if (module != null) {
                            sb.append(String.format("[%" + maxLengthSoName.length() + "s]", module.name));
                            sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", lr.peer - module.base + (thumb ? 1 : 0)));
                        } else {
                            sb.append(String.format("[%" + maxLengthSoName.length() + "s]", "0x" + Long.toHexString(lr == null ? 0 : lr.peer)));
                            if (lr != null) {
                                sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", lr.peer - 0xfffe0000L + (thumb ? 1 : 0)));
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
                    continue;
                }
                if (line.startsWith("b0x")) {
                    try {
                        long addr = Long.parseLong(line.substring(3), 16) & 0xfffffffffffffffeL;
                        Module module = null;
                        if (addr < Memory.MMAP_BASE && (module = findModuleByAddress(address)) != null) {
                            addr += module.base;
                        }
                        breakMap.put(addr, null); // temp breakpoint
                        if (module == null) {
                            module = findModuleByAddress(addr);
                        }
                        System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                        continue;
                    } catch(NumberFormatException ignored) {
                    }
                }
                if ("blr".equals(line)) { // break LR
                    long addr = ((Number) u.reg_read(ArmConst.UC_ARM_REG_LR)).intValue() & 0xffffffffL;
                    breakMap.put(addr, null);
                    Module module = findModuleByAddress(addr);
                    System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    continue;
                }
                if ("r".equals(line)) {
                    long addr = ((Number) u.reg_read(ArmConst.UC_ARM_REG_PC)).intValue() & 0xffffffffL;
                    if (breakMap.containsKey(addr)) {
                        breakMap.remove(addr);
                        Module module = findModuleByAddress(addr);
                        System.out.println("Remove breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    }
                    continue;
                }
                if ("b".equals(line)) {
                    long addr = ((Number) u.reg_read(ArmConst.UC_ARM_REG_PC)).intValue() & 0xffffffffL;
                    breakMap.put(addr, null);
                    Module module = findModuleByAddress(addr);
                    System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    continue;
                }
                if ("c".equals(line)) { // continue
                    break;
                }
                if ("n".equals(line)) {
                    if (nextAddress == 0) {
                        System.out.println("Next address failed.");
                        continue;
                    } else {
                        breakMap.put(nextAddress, null);
                        break;
                    }
                }
                if ("stop".equals(line)) {
                    u.emu_stop();
                    break;
                }
                if ("s".equals(line) || "si".equals(line)) {
                    singleStep = 1;
                    break;
                }
                if (line.startsWith("s")) {
                    try {
                        singleStep = Integer.parseInt(line.substring(1));
                        break;
                    } catch (NumberFormatException e) {
                        breakMnemonic = line.substring(1);
                        break;
                    }
                }

                showHelp();
            } catch (RuntimeException e) {
                e.printStackTrace();
            }
        }
    }

    private void showHelp() {
        System.out.println("c: continue");
        System.out.println("n: step over");
        System.out.println("bt: back trace");
        System.out.println();
        System.out.println("s|si: step into");
        System.out.println("s[decimal]: execute specified amount instruction");
        System.out.println("sblx: execute util BLX mnemonic");
        System.out.println();
        System.out.println("m(op) [size]: show memory, default size is 0x70, size may hex or decimal");
        System.out.println("mr0-mr7, mfp, mip, msp [size]: show memory of specified register");
        System.out.println("m(address) [size]: show memory of specified address, address must start with 0x");
        System.out.println();
        System.out.println("b(address): add temporarily breakpoint, address must start with 0x, can be module offset");
        System.out.println("b: add breakpoint of register PC");
        System.out.println("r: remove breakpoint of register PC");
        System.out.println("blr: add temporarily breakpoint of register LR");
        System.out.println();
        System.out.println("d|dis: show disassemble");
        System.out.println("stop: stop emulation");
    }

}
