package cn.banny.unidbg.arm;

import capstone.Capstone;
import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.debugger.DebugListener;
import cn.banny.unidbg.debugger.Debugger;
import cn.banny.unidbg.memory.MemRegion;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.utils.Hex;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;

public abstract class AbstractARMDebugger implements Debugger {

    private static final Log log = LogFactory.getLog(AbstractARMDebugger.class);

    private final Map<Long, Module> breakMap = new HashMap<>();

    protected final Emulator emulator;
    private final boolean softBreakpoint;

    protected AbstractARMDebugger(Emulator emulator, boolean softBreakpoint) {
        this.emulator = emulator;
        this.softBreakpoint = softBreakpoint;
    }

    @Override
    public final void addBreakPoint(Module module, String symbol) {
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
    public final void addBreakPoint(Module module, long offset) {
        long address = module == null ? offset : module.base + offset;
        addBreakPoint(address);
    }

    private class SoftBreakPoint {
        final long address;
        final byte[] backup;
        SoftBreakPoint(long address, byte[] backup) {
            this.address = address;
            this.backup = backup;
        }
    }

    private final Map<Integer, SoftBreakPoint> softBreakpointMap = new HashMap<>();

    private int svcNumber = 1;

    @Override
    public void addBreakPoint(long address) {
        if (softBreakpoint) {
            int svcNumber = ++this.svcNumber; // begin with 2
            byte[] code = addSoftBreakPoint(address, svcNumber);

            address &= (~1);
            Pointer pointer = UnicornPointer.pointer(emulator, address);
            assert pointer != null;
            byte[] backup = pointer.getByteArray(0, code.length);
            pointer.write(0, code, 0, code.length);
            softBreakpointMap.put(svcNumber, new SoftBreakPoint(address, backup));
        } else {
            address &= (~1);

            if (log.isDebugEnabled()) {
                log.debug("addBreakPoint address=0x" + Long.toHexString(address));
            }
            breakMap.put(address, emulator.getMemory().findModuleByAddress(address));
        }
    }

    protected abstract byte[] addSoftBreakPoint(long address, int svcNumber);

    public final boolean removeBreakPoint(long address) {
        if (softBreakpoint) {
            for (Iterator<Map.Entry<Integer, SoftBreakPoint>> iterator = softBreakpointMap.entrySet().iterator(); iterator.hasNext(); ) {
                Map.Entry<Integer, SoftBreakPoint> entry = iterator.next();
                SoftBreakPoint breakPoint = entry.getValue();
                if (address == breakPoint.address) {
                    Pointer pointer = UnicornPointer.pointer(emulator, address);
                    assert pointer != null;
                    pointer.write(0, breakPoint.backup, 0, breakPoint.backup.length);
                    iterator.remove();
                    return true;
                }
            }
            return false;
        } else {
            if (breakMap.containsKey(address)) {
                breakMap.remove(address);
                return true;
            } else {
                return false;
            }
        }
    }

    private final List<CodeHistory> historyList = new ArrayList<>(15);

    private DebugListener listener;

    @Override
    public void setDebugListener(DebugListener listener) {
        this.listener = listener;
    }

    @Override
    public final void hook(Unicorn u, long address, int size, Object user) {
        Emulator emulator = (Emulator) user;

        while (historyList.size() > 10) {
            historyList.remove(0);
        }
        CodeHistory history = new CodeHistory(address, size, ARM.isThumb(u));
        historyList.add(history);

        if (singleStep >= 0) {
            singleStep--;
        }

        try {
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
        } catch (Exception e) {
            log.warn("process hook failed", e);
        }
    }

    @Override
    public void debug() {
        Unicorn unicorn = emulator.getUnicorn();
        long address;
        if (emulator.getPointerSize() == 4) {
            address = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_PC)).intValue() & 0xffffffffL;
        } else {
            address = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_PC)).longValue();
        }
        try {
            loop(emulator, unicorn, address, 0);
        } catch (Exception e) {
            log.warn("debug failed", e);
        }
    }

    int singleStep;

    String breakMnemonic;

    protected abstract void loop(Emulator emulator, Unicorn u, long address, int size) throws Exception;

    final void dumpMemory(Pointer pointer, int _length, String label, boolean nullTerminated) {
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

    /**
     * @return next address
     */
    final long disassemble(Emulator emulator, long address, int size, boolean thumb) {
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

    final Module findModuleByAddress(long address) {
        Memory memory = emulator.getMemory();
        Module module = memory.findModuleByAddress(address);
        if (module == null) {
            MemRegion region = emulator.getSvcMemory().findRegion(address);
            if (region != null) {
                String name = region.getName();
                int maxLength = memory.getMaxLengthLibraryName().length();
                if (name.length() > maxLength) {
                    name = name.substring(name.length() - maxLength);
                }
                module = new Module(name, region.begin, region.end - region.begin, Collections.<String, Module>emptyMap(), Collections.<MemRegion>emptyList()) {
                    @Override
                    public Number[] callFunction(Emulator emulator, long offset, Object... args) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public Symbol findSymbolByName(String name, boolean withDependencies) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public Symbol findNearestSymbolByAddress(long addr) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public int callEntry(Emulator emulator, Object... args) {
                        throw new UnsupportedOperationException();
                    }
                };
            }
        }
        return module;
    }

    @Override
    public final void brk(Pointer pc, int svcNumber) {
        SoftBreakPoint breakPoint = softBreakpointMap.get(svcNumber);
        if (breakPoint == null) {
            debug();
        } else {
            if (log.isDebugEnabled()) {
                log.debug(Inspector.inspectString(breakPoint.backup, "brk pc=" + pc + ", svcNumber=" + svcNumber + ", address=0x" + Long.toHexString(breakPoint.address)));
            }
            pc.write(0, breakPoint.backup, 0, breakPoint.backup.length);
            debug();
        }
    }

    @Override
    public void close() {
    }

}
