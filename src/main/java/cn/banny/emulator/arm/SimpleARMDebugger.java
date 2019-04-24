package cn.banny.emulator.arm;

import capstone.Capstone;
import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import cn.banny.emulator.Symbol;
import cn.banny.emulator.debugger.DebugListener;
import cn.banny.emulator.debugger.Debugger;
import cn.banny.emulator.linux.android.AndroidARMEmulator;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.utils.Hex;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;

public class SimpleARMDebugger implements Debugger {

    private static final Log log = LogFactory.getLog(SimpleARMDebugger.class);

    private final Map<Long, Module> breakMap = new HashMap<>();

    @Override
    public void addBreakPoint(Module module, String symbol) {
        try {
            Symbol sym = module.findSymbolByName(symbol, false);
            if (sym == null) {
                throw new IllegalStateException("find symbol failed: " + symbol);
            }
            addBreakPoint(module, sym.getValue());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void addBreakPoint(Module module, long offset) {
        long address = (module == null ? offset : module.base + offset) & (~1);
        if (log.isDebugEnabled()) {
            log.debug("addBreakPoint address=0x" + Long.toHexString(address));
        }
        breakMap.put(address, module);
    }

    private final List<CodeHistory> historyList = new ArrayList<>(15);

    private DebugListener listener;

    @Override
    public void setDebugListener(DebugListener listener) {
        this.listener = listener;
    }

    @Override
    public void hook(Unicorn u, long address, int size, Object user) {
        Emulator emulator = (Emulator) user;

        while (historyList.size() > 10) {
            historyList.remove(0);
        }
        CodeHistory history = new CodeHistory(address, size, ARM.isThumb(u));
        historyList.add(history);

        if (singleStep >= 0) {
            singleStep--;
        }

        if (breakMap.containsKey(address)) {
            loop(emulator, u, address, size);
        } else if (singleStep == 0) {
            loop(emulator, u, address, size);
        } else if (breakMnemonic != null) {
            Capstone.CsInsn ins = history.disassemble(emulator);
            if (breakMnemonic.equals(ins.mnemonic)) {
                breakMnemonic = null;
                loop(emulator, u, address, size);
            }
        } else if (listener != null && listener.canDebug(emulator, history)) {
            loop(emulator, u, address, size);
        }
    }

    @Override
    public void debug(Emulator emulator) {
        Unicorn unicorn = emulator.getUnicorn();
        long address;
        if (emulator.getPointerSize() == 4) {
            address = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_PC)).intValue() & 0xffffffffL;
        } else {
            address = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_PC)).longValue();
        }
        loop(emulator, unicorn, address, 0);
    }

    private int singleStep;

    private void loop(Emulator emulator, Unicorn u, long address, int size) {
        final boolean isARM32 = emulator.getPointerSize() == 4;
        System.out.println("debugger break at: 0x" + Long.toHexString(address));
        boolean thumb = isARM32 && ARM.isThumb(u);
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
                    if (command.startsWith("mr") && command.length() == 3 && isARM32) {
                        char c = command.charAt(2);
                        if (c >= '0' && c <= '7') {
                            int r = c - '0';
                            reg = ArmConst.UC_ARM_REG_R0 + r;
                            name = "r" + r;
                        }
                    } else if (command.startsWith("mx") && (command.length() == 3 || command.length() == 4) && !isARM32) {
                        int idx = Integer.parseInt(command.substring(2));
                        if (idx >= 0 && idx <= 28) {
                            reg = Arm64Const.UC_ARM64_REG_X0 + idx;
                            name = "x" + idx;
                        }
                    } else if ("mfp".equals(command)) {
                        reg = isARM32 ? ArmConst.UC_ARM_REG_FP : Arm64Const.UC_ARM64_REG_FP;
                        name = "fp";
                    } else if ("mip".equals(command)) {
                        reg = isARM32 ? ArmConst.UC_ARM_REG_IP : Arm64Const.UC_ARM64_REG_IP0;
                        name = "ip";
                    } else if ("msp".equals(command)) {
                        reg = isARM32 ? ArmConst.UC_ARM_REG_SP : Arm64Const.UC_ARM64_REG_SP;
                        name = "sp";
                    } else if (command.startsWith("m0x")) {
                        long addr = Long.parseLong(command.substring(3), 16);
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
                if ("bt".equals(line) && isARM32) {
                    Memory memory = emulator.getMemory();
                    String maxLengthSoName = memory.getMaxLengthLibraryName();
                    boolean hasTrace = false;
                    UnicornPointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                    UnicornPointer lr = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR);
                    UnicornPointer r7 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R7);
                    do {
                        Module module = memory.findModuleByAddress(lr.peer);
                        if (lr.peer == AndroidARMEmulator.LR) {
                            break;
                        }

                        hasTrace = true;
                        StringBuilder sb = new StringBuilder();
                        if (module != null) {
                            sb.append(String.format("[%" + maxLengthSoName.length() + "s]", module.name));
                            sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", lr.peer - module.base + (thumb ? 1 : 0)));
                        } else {
                            sb.append(String.format("[%" + maxLengthSoName.length() + "s]", "0x" + Long.toHexString(lr.peer)));
                            sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x]", lr.peer - 0xfffe0000L + (thumb ? 1 : 0)));
                        }
                        System.out.println(sb);

                        if (r7.peer < sp.peer) {
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
                        long addr = Long.parseLong(line.substring(3), 16) & 0xFFFFFFFFFFFFFFFEL;
                        Module module = null;
                        if (addr < Memory.MMAP_BASE && (module = emulator.getMemory().findModuleByAddress(address)) != null) {
                            addr += module.base;
                        }
                        breakMap.put(addr, null); // temp breakpoint
                        if (module == null) {
                            module = emulator.getMemory().findModuleByAddress(address);
                        }
                        System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                        continue;
                    } catch(NumberFormatException ignored) {
                    }
                }
                if ("blr".equals(line)) { // break LR
                    long addr;
                    if (isARM32) {
                        addr = ((Number) u.reg_read(ArmConst.UC_ARM_REG_LR)).intValue() & 0xffffffffL;
                    } else {
                        addr = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_LR)).longValue();
                    }
                    breakMap.put(addr, null);
                    Module module = emulator.getMemory().findModuleByAddress(address);
                    System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    continue;
                }
                if ("r".equals(line)) {
                    long addr;
                    if (isARM32) {
                        addr = ((Number) u.reg_read(ArmConst.UC_ARM_REG_PC)).intValue() & 0xffffffffL;
                    } else {
                        addr = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_PC)).longValue();
                    }
                    if (breakMap.containsKey(addr)) {
                        breakMap.remove(addr);
                        Module module = emulator.getMemory().findModuleByAddress(address);
                        System.out.println("Remove breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                    }
                    continue;
                }
                if ("b".equals(line)) {
                    long addr;
                    if (isARM32) {
                        addr = ((Number) u.reg_read(ArmConst.UC_ARM_REG_PC)).intValue() & 0xffffffffL;
                    } else {
                        addr = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_PC)).longValue();
                    }
                    breakMap.put(addr, null);
                    Module module = emulator.getMemory().findModuleByAddress(address);
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
            } catch (UnicornException e) {
                e.printStackTrace();
            }
        }
    }

    private void dumpMemory(Pointer pointer, int _length, String label, boolean nullTerminated) {
        if (nullTerminated) {
            long addr = 0;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            boolean foundTerminated = false;
            while (true) {
                byte[] data = pointer.getByteArray(addr, 0x100);
                int length = data.length;
                for (int i = 0; i < data.length; i++) {
                    if (data[i] == 0) {
                        length = i;
                        break;
                    }
                }
                baos.write(data, 0, length);
                addr += length;

                if (length < data.length) { // reach zero
                    foundTerminated = true;
                    break;
                }

                if (baos.size() > 0x10000) { // 64k
                    break;
                }
            }

            if (foundTerminated) {
                Inspector.inspect(baos.toByteArray(), baos.size() >= 1024 ? (label + ", hex=" + Hex.encodeHexString(baos.toByteArray())) : label);
            } else {
                Inspector.inspect(pointer.getByteArray(0, _length), label + ", find NULL-terminated failed");
            }
        } else {
            byte[] data = pointer.getByteArray(0, _length);
            Inspector.inspect(data, data.length >= 1024 ? (label + ", hex=" + Hex.encodeHexString(data)) : label);
        }
    }

    private String breakMnemonic;

    /**
     * @return next address
     */
    private long disassemble(Emulator emulator, long address, int size, boolean thumb) {
        long next = 0;
        boolean on = false;
        StringBuilder sb = new StringBuilder();
        for (CodeHistory history : historyList) {
            if (history.address == address) {
                sb.append("=> *");
                on = true;
            } else {
                sb.append("    ");
                if (on) {
                    next = history.address;
                    on = false;
                }
            }
            Capstone.CsInsn ins = history.disassemble(emulator);
            sb.append(ARM.assembleDetail(emulator.getMemory(), ins, history.address, history.thumb, on ? '*' : ' ')).append('\n');
        }
        long nextAddr = address + size;
        Capstone.CsInsn[] insns = emulator.disassemble(nextAddr, 4 * 10, 10);
        for (Capstone.CsInsn ins : insns) {
            if (nextAddr == address) {
                sb.append("=> *");
                on = true;
            } else {
                sb.append("    ");
                if (on) {
                    next = nextAddr;
                    on = false;
                }
            }
            sb.append(ARM.assembleDetail(emulator.getMemory(), ins, nextAddr, thumb, on ? '*' : ' ')).append('\n');
            nextAddr += ins.size;
        }
        System.out.println(sb);
        return next;
    }

}
