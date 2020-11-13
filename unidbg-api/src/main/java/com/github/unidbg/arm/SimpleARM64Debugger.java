package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Family;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneMode;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import unicorn.Arm64Const;

import java.util.Scanner;
import java.util.concurrent.Callable;

class SimpleARM64Debugger extends AbstractARMDebugger implements Debugger {

    SimpleARM64Debugger(Emulator<?> emulator) {
        super(emulator);
    }

    @Override
    protected final void loop(Emulator<?> emulator, long address, int size, Callable<?> callable) throws Exception {
        Backend backend = emulator.getBackend();
        long nextAddress = 0;
        if (address > 0) {
            System.out.println("debugger break at: 0x" + Long.toHexString(address));
            try {
                emulator.showRegs();
                nextAddress = disassemble(emulator, address, size, false);
            } catch (BackendException e) {
                e.printStackTrace();
            }
        }

        Scanner scanner = new Scanner(System.in);
        String line;
        while ((line = scanner.nextLine()) != null) {
            try {
                if ("help".equals(line)) {
                    showHelp();
                    continue;
                }
                if ("run".equals(line) && callable != null) {
                    try {
                        callbackRunning = true;
                        callable.call();
                    } finally {
                        callbackRunning = false;
                    }
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
                    StringType stringType = null;
                    if (command.endsWith("s")) {
                        stringType = StringType.nullTerminated;
                        command = command.substring(0, command.length() - 1);
                    } else if (command.endsWith("std")) {
                        stringType = StringType.std_string;
                        command = command.substring(0, command.length() - 3);
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
                        Pointer pointer = UnidbgPointer.pointer(emulator, addr);
                        if (pointer != null) {
                            dumpMemory(pointer, length, pointer.toString(), stringType);
                        } else {
                            System.out.println(addr + " is null");
                        }
                        continue;
                    }
                    if (reg != -1) {
                        Pointer pointer = UnidbgPointer.register(emulator, reg);
                        if (pointer != null) {
                            dumpMemory(pointer, length, name + "=" + pointer, stringType);
                        } else {
                            System.out.println(name + " is null");
                        }
                        continue;
                    }
                }
                if ("where".equals(line)) {
                    new Exception("here").printStackTrace(System.out);
                    continue;
                }
                if (line.startsWith("wx0x")) {
                    String[] tokens = line.split("\\s+");
                    long addr = Long.parseLong(tokens[0].substring(4).trim(), 16);
                    Pointer pointer = UnidbgPointer.pointer(emulator, addr);
                    if (pointer != null && tokens.length > 1) {
                        byte[] data = Hex.decodeHex(tokens[1].toCharArray());
                        pointer.write(0, data, 0, data.length);
                        dumpMemory(pointer, data.length, pointer.toString(), null);
                    } else {
                        System.out.println(addr + " is null");
                    }
                    continue;
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
                        Pointer pointer = UnidbgPointer.pointer(emulator, addr);
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
                            dumpMemory(pointer, 16, pointer.toString(), null);
                        } else {
                            System.out.println(addr + " is null");
                        }
                        continue;
                    }
                    if (reg != -1) {
                        backend.reg_write(reg, value);
                        ARM.showRegs64(emulator, new int[] { reg });
                        continue;
                    }
                }
                if (emulator.isRunning() && "bt".equals(line)) {
                    try {
                        emulator.getUnwinder().unwind();
                    } catch (Throwable e) {
                        e.printStackTrace();
                    }
                    continue;
                }
                if (line.startsWith("b0x")) {
                    try {
                        long addr = Long.parseLong(line.substring(3), 16) & 0xfffffffffffffffeL;
                        Module module = null;
                        if (addr < Memory.MMAP_BASE && (module = findModuleByAddress(emulator, address)) != null) {
                            addr += module.base;
                        }
                        addBreakPoint(addr); // temp breakpoint
                        if (module == null) {
                            module = findModuleByAddress(emulator, addr);
                        }
                        System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                        continue;
                    } catch(NumberFormatException ignored) {
                    }
                }
                if ("blr".equals(line)) { // break LR
                    long addr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
                    addBreakPoint(addr);
                    Module module = findModuleByAddress(emulator, addr);
                    System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    continue;
                }
                if ("r".equals(line)) {
                    long addr = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                    if (removeBreakPoint(addr)) {
                        Module module = findModuleByAddress(emulator, addr);
                        System.out.println("Remove breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    }
                    continue;
                }
                if ("b".equals(line)) {
                    long addr = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                    addBreakPoint(addr);
                    Module module = findModuleByAddress(emulator, addr);
                    System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    continue;
                }
                if(handleCommon(backend, line, address, size, nextAddress, callable)) {
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
        if (emulator.isRunning()) {
            System.out.println("bt: back trace");
        }
        System.out.println();
        System.out.println("st hex: search stack");
        System.out.println("shw hex: search writable heap");
        System.out.println("shr hex: search readable heap");
        System.out.println("shx hex: search executable heap");
        System.out.println();
        System.out.println("s|si: step into");
        System.out.println("s[decimal]: execute specified amount instruction");
        System.out.println("s(bl): execute util BL mnemonic, low performance");
        System.out.println();
        System.out.println("m(op) [size]: show memory, default size is 0x70, size may hex or decimal");
        System.out.println("mx0-mx28, mfp, mip, msp [size]: show memory of specified register");
        System.out.println("m(address) [size]: show memory of specified address, address must start with 0x");
        System.out.println();
        System.out.println("wx0-wx28, wfp, wip, wsp <value>: write specified register");
        System.out.println("wb(address), ws(address), wi(address), wl(address) <value>: write (byte, short, integer, long) memory of specified address, address must start with 0x");
        System.out.println("wx(address) <hex>: write bytes to memory at specified address, address must start with 0x");
        System.out.println();
        System.out.println("b(address): add temporarily breakpoint, address must start with 0x, can be module offset");
        System.out.println("b: add breakpoint of register PC");
        System.out.println("r: remove breakpoint of register PC");
        System.out.println("blr: add temporarily breakpoint of register LR");
        System.out.println();
        System.out.println("p (assembly): patch assembly at PC address");
        System.out.println("where: show java stack trace");
        System.out.println();
        System.out.println("trace [begin end]: Set trace instructions");
        System.out.println("vm: view loaded modules");
        System.out.println("vbs: view breakpoints");
        System.out.println("d|dis: show disassemble");
        System.out.println("d(0x): show disassemble at specify address");
        System.out.println("stop: stop emulation");
        System.out.println("run: run test");

        if (emulator.getFamily() == Family.iOS && !emulator.isRunning()) {
            System.out.println("dump [class name]: dump objc class");
            System.out.println("search [keywords]: search objc classes");
        }
    }

    @Override
    protected Keystone createKeystone(boolean isThumb) {
        return new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);
    }

}
