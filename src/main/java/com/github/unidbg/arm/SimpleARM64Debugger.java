package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneMode;
import org.apache.commons.codec.DecoderException;
import unicorn.Arm64Const;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.util.Scanner;

class SimpleARM64Debugger extends AbstractARMDebugger implements Debugger {

    SimpleARM64Debugger(Emulator<?> emulator, boolean softBreakpoint) {
        super(emulator, softBreakpoint);
    }

    @Override
    protected final void loop(Emulator<?> emulator, long address, int size) {
        System.out.println("debugger break at: 0x" + Long.toHexString(address));
        Unicorn u = emulator.getUnicorn();
        long nextAddress = 0;
        try {
            emulator.showRegs();
            nextAddress = disassemble(emulator, address, size, false);
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
                    disassemble(emulator, address, size, false);
                    continue;
                }
                if (line.startsWith("d0x")) {
                    disassembleBlock(emulator, Long.parseLong(line.substring(3), 16), false);
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
                    if (command.startsWith("mx") && (command.length() == 3 || command.length() == 4)) {
                        int idx = Integer.parseInt(command.substring(2));
                        if (idx >= 0 && idx <= 28) {
                            reg = Arm64Const.UC_ARM64_REG_X0 + idx;
                            name = "x" + idx;
                        }
                    } else if ("mfp".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_FP;
                        name = "fp";
                    } else if ("mip".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_IP0;
                        name = "ip";
                    } else if ("msp".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_SP;
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
                if (line.startsWith("w")) {
                    String command;
                    String[] tokens = line.split("\\s+");
                    if (tokens.length < 2) {
                        System.out.println("wx0-wx28, wfp, wip, wsp <value>: write specified register");
                        System.out.println("wb(address), ws(address), wi(address), wl(address) <value>: write (byte, short, integer, long) memory of specified address, address must start with 0x");
                        continue;
                    }
                    long value;
                    try {
                        command = tokens[0];
                        int radix = 10;
                        String str = tokens[1];
                        if (str.startsWith("0x")) {
                            str = str.substring(2);
                            radix = 16;
                        }
                        value = Long.parseLong(str, radix);
                    } catch(NumberFormatException e) {
                        e.printStackTrace();
                        continue;
                    }

                    int reg = -1;
                    if (command.startsWith("wx") && (command.length() == 3 || command.length() == 4)) {
                        int idx = Integer.parseInt(command.substring(2));
                        if (idx >= 0 && idx <= 28) {
                            reg = Arm64Const.UC_ARM64_REG_X0 + idx;
                        }
                    } else if ("wfp".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_FP;
                    } else if ("wip".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_IP0;
                    } else if ("wsp".equals(command)) {
                        reg = Arm64Const.UC_ARM64_REG_SP;
                    } else if (command.startsWith("wb0x") || command.startsWith("ws0x") || command.startsWith("wi0x") || command.startsWith("wl0x")) {
                        long addr = Long.parseLong(command.substring(4).trim(), 16);
                        Pointer pointer = UnicornPointer.pointer(emulator, addr);
                        if (pointer != null) {
                            if (command.startsWith("wb")) {
                                pointer.setByte(0, (byte) value);
                            } else if (command.startsWith("ws")) {
                                pointer.setShort(0, (short) value);
                            } else if (command.startsWith("wi")) {
                                pointer.setInt(0, (int) value);
                            } else if (command.startsWith("wl")) {
                                pointer.setLong(0, value);
                            }
                            dumpMemory(pointer, 16, pointer.toString(), false);
                        } else {
                            System.out.println(addr + " is null");
                        }
                        continue;
                    }
                    if (reg != -1) {
                        Unicorn unicorn = emulator.getUnicorn();
                        unicorn.reg_write(reg, value);
                        ARM.showRegs64(emulator, new int[] { reg });
                        continue;
                    }
                }
                if ("bt".equals(line)) {
                    Memory memory = emulator.getMemory();
                    String maxLengthSoName = memory.getMaxLengthLibraryName();
                    boolean hasTrace = false;
                    UnicornPointer lr = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR);
                    UnicornPointer fp = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_FP);
                    do {
                        Module module = null;
                        if (lr != null) {
                            module = findModuleByAddress(lr.peer);
                            if (lr.peer == AbstractARM64Emulator.LR) {
                                break;
                            }
                        }

                        hasTrace = true;
                        StringBuilder sb = new StringBuilder();
                        if (module != null) {
                            sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", module.base));
                            sb.append(String.format("[%" + maxLengthSoName.length() + "s]", module.name));
                            sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", lr.peer - module.base));
                        } else {
                            sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", 0L));
                            sb.append(String.format("[%" + maxLengthSoName.length() + "s]", "0x" + Long.toHexString(lr == null ? 0 : lr.peer)));
                            if (lr != null) {
                                sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", lr.peer - 0xfffe0000L));
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
                    continue;
                }
                if (line.startsWith("b0x")) {
                    try {
                        long addr = Long.parseLong(line.substring(3), 16) & 0xfffffffffffffffeL;
                        Module module = null;
                        if (addr < Memory.MMAP_BASE && (module = findModuleByAddress(address)) != null) {
                            addr += module.base;
                        }
                        addBreakPoint(addr); // temp breakpoint
                        if (module == null) {
                            module = findModuleByAddress(addr);
                        }
                        System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                        continue;
                    } catch(NumberFormatException ignored) {
                    }
                }
                if ("blr".equals(line)) { // break LR
                    long addr = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_LR)).longValue();
                    addBreakPoint(addr);
                    Module module = findModuleByAddress(addr);
                    System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    continue;
                }
                if ("r".equals(line)) {
                    long addr = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_PC)).longValue();
                    if (removeBreakPoint(addr)) {
                        Module module = findModuleByAddress(addr);
                        System.out.println("Remove breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    }
                    continue;
                }
                if ("b".equals(line)) {
                    long addr = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_PC)).longValue();
                    addBreakPoint(addr);
                    Module module = findModuleByAddress(addr);
                    System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    continue;
                }
                if(handleCommon(u, line, address, size, nextAddress)) {
                    break;
                }
            } catch (RuntimeException | DecoderException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    final void showHelp() {
        System.out.println("c: continue");
        System.out.println("n: step over");
        System.out.println("bt: back trace");
        System.out.println();
        System.out.println("st hex: search stack");
        System.out.println("shw hex: search writable heap");
        System.out.println("shr hex: search readable heap");
        System.out.println("shx hex: search executable heap");
        System.out.println();
        System.out.println("s|si: step into");
        System.out.println("s[decimal]: execute specified amount instruction");
        System.out.println("s(bl): execute util BL mnemonic");
        System.out.println();
        System.out.println("m(op) [size]: show memory, default size is 0x70, size may hex or decimal");
        System.out.println("mx0-mx28, mfp, mip, msp [size]: show memory of specified register");
        System.out.println("m(address) [size]: show memory of specified address, address must start with 0x");
        System.out.println();
        System.out.println("wx0-wx28, wfp, wip, wsp <value>: write specified register");
        System.out.println("wb(address), ws(address), wi(address), wl(address) <value>: write (byte, short, integer, long) memory of specified address, address must start with 0x");
        System.out.println();
        System.out.println("b(address): add temporarily breakpoint, address must start with 0x, can be module offset");
        System.out.println("b: add breakpoint of register PC");
        System.out.println("r: remove breakpoint of register PC");
        System.out.println("blr: add temporarily breakpoint of register LR");
        System.out.println();
        System.out.println("p (assembly): patch assembly at PC address");
        System.out.println();
        System.out.println("vm: view loaded modules");
        System.out.println("d|dis: show disassemble");
        System.out.println("d(0x): show disassemble at specify address");
        System.out.println("stop: stop emulation");
    }

    @Override
    protected Keystone createKeystone(boolean isThumb) {
        return new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);
    }

}
