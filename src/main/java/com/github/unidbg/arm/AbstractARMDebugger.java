package com.github.unidbg.arm;

import capstone.Capstone;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.debugger.DebugListener;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneEncoded;
import keystone.exceptions.AssembleFailedKeystoneException;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public abstract class AbstractARMDebugger implements Debugger {

    private static final Log log = LogFactory.getLog(AbstractARMDebugger.class);

    private static class BreakPointImpl implements BreakPoint {
        final BreakPointCallback callback;
        boolean isTemporary;
        public BreakPointImpl(BreakPointCallback callback) {
            this.callback = callback;
        }
        @Override
        public void setTemporary(boolean temporary) {
            this.isTemporary = true;
        }
    }

    private final Map<Long, BreakPointImpl> breakMap = new HashMap<>();

    protected final Emulator<?> emulator;
    private final boolean softBreakpoint;

    protected AbstractARMDebugger(Emulator<?> emulator, boolean softBreakpoint) {
        this.emulator = emulator;
        this.softBreakpoint = softBreakpoint;
    }

    @Override
    public boolean isSoftBreakpoint() {
        return softBreakpoint;
    }

    @Override
    public final BreakPoint addBreakPoint(Module module, String symbol) {
        Symbol sym = module.findSymbolByName(symbol, false);
        if (sym == null) {
            throw new IllegalStateException("find symbol failed: " + symbol);
        }
        return addBreakPoint(module, sym.getValue());
    }

    @Override
    public final BreakPoint addBreakPoint(Module module, String symbol, BreakPointCallback callback) {
        Symbol sym = module.findSymbolByName(symbol, false);
        if (sym == null) {
            throw new IllegalStateException("find symbol failed: " + symbol);
        }
        return addBreakPoint(module, sym.getValue(), callback);
    }

    @Override
    public final BreakPoint addBreakPoint(Module module, long offset) {
        long address = module == null ? offset : module.base + offset;
        return addBreakPoint(address);
    }

    @Override
    public final BreakPoint addBreakPoint(Module module, long offset, BreakPointCallback callback) {
        long address = module == null ? offset : module.base + offset;
        return addBreakPoint(address, callback);
    }

    private static class SoftBreakPoint implements BreakPoint {
        final long address;
        final byte[] backup;
        final BreakPointCallback callback;
        SoftBreakPoint(long address, byte[] backup, BreakPointCallback callback) {
            this.address = address;
            this.backup = backup;
            this.callback = callback;
        }
        @Override
        public void setTemporary(boolean temporary) {
            throw new UnsupportedOperationException();
        }
    }

    private final Map<Integer, SoftBreakPoint> softBreakpointMap = new HashMap<>();

    private int svcNumber = 1;

    @Override
    public BreakPoint addBreakPoint(long address) {
        return addBreakPoint(address, null);
    }

    @Override
    public BreakPoint addBreakPoint(long address, BreakPointCallback callback) {
        if (softBreakpoint) {
            int svcNumber = ++this.svcNumber; // begin with 2
            byte[] code = addSoftBreakPoint(address, svcNumber);

            address &= (~1);
            Pointer pointer = UnicornPointer.pointer(emulator, address);
            assert pointer != null;
            byte[] backup = pointer.getByteArray(0, code.length);
            pointer.write(0, code, 0, code.length);
            SoftBreakPoint breakPoint = new SoftBreakPoint(address, backup, callback);
            softBreakpointMap.put(svcNumber, breakPoint);
            return breakPoint;
        } else {
            address &= (~1);

            if (log.isDebugEnabled()) {
                log.debug("addBreakPoint address=0x" + Long.toHexString(address));
            }
            BreakPointImpl breakPoint = new BreakPointImpl(callback);
            breakMap.put(address, breakPoint);
            return breakPoint;
        }
    }

    protected final byte[] addSoftBreakPoint(long address, int svcNumber) {
        if (emulator.is64Bit()) {
            try (Keystone keystone = createKeystone(false)) {
                KeystoneEncoded encoded = keystone.assemble("brk #" + svcNumber);
                return encoded.getMachineCode();
            }
        } else {
            boolean isThumb = (address & 1) != 0;
            try (Keystone keystone = createKeystone(isThumb)) {
                KeystoneEncoded encoded = keystone.assemble("bkpt #" + svcNumber);
                return encoded.getMachineCode();
            }
        }
    }

    protected abstract Keystone createKeystone(boolean isThumb);

    public final boolean removeBreakPoint(long address) {
        address &= (~1);

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
        Emulator<?> emulator = (Emulator<?>) user;

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
                BreakPointImpl breakPoint = breakMap.get(address);
                if (breakPoint != null && breakPoint.isTemporary) {
                    breakMap.remove(address);
                }
                if (breakPoint != null && (breakPoint.callback == null || breakPoint.callback.onHit(emulator, address))) {
                    loop(emulator, address, size);
                }
            } else if (singleStep == 0) {
                loop(emulator, address, size);
            } else if (breakMnemonic != null) {
                Capstone.CsInsn ins = history.disassemble(emulator);
                if (breakMnemonic.equals(ins.mnemonic)) {
                    breakMnemonic = null;
                    loop(emulator, address, size);
                }
            } else if (listener != null && listener.canDebug(emulator, history)) {
                loop(emulator, address, size);
            }
        } catch (Exception e) {
            log.warn("process hook failed", e);
        }
    }

    @Override
    public void debug() {
        Unicorn unicorn = emulator.getUnicorn();
        long address;
        if (emulator.is32Bit()) {
            address = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_PC)).intValue() & 0xffffffffL;
        } else {
            address = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_PC)).longValue();
        }
        try {
            loop(emulator, address, 0);
        } catch (Exception e) {
            log.warn("debug failed", e);
        }
    }

    protected int singleStep;

    String breakMnemonic;

    protected abstract void loop(Emulator<?> emulator, long address, int size) throws Exception;

    final void dumpMemory(Pointer pointer, int _length, String label, boolean nullTerminated) {
        if (nullTerminated) {
            long addr = 0;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            boolean foundTerminated = false;
            while (true) {
                byte[] data = pointer.getByteArray(addr, 0x10);
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
            StringBuilder sb = new StringBuilder(label);
            byte[] data = pointer.getByteArray(0, _length);
            if (_length == 4) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                int value = buffer.getInt();
                sb.append(", value=0x").append(Integer.toHexString(value));
            } else if (_length == 8) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                long value = buffer.getLong();
                sb.append(", value=0x").append(Long.toHexString(value));
            }
            if (data.length >= 1024) {
                sb.append(", hex=").append(Hex.encodeHexString(data));
            }
            Inspector.inspect(data, sb.toString());
        }
    }

    private void searchStack(byte[] data) {
        if (data == null || data.length < 1) {
            System.err.println("search stack failed as empty data");
            return;
        }

        UnicornPointer stack = emulator.getContext().getStackPointer();
        Unicorn unicorn = emulator.getUnicorn();
        Collection<Pointer> pointers = searchMemory(unicorn, stack.toUIntPeer(), emulator.getMemory().getStackBase(), data);
        System.out.println("Search stack from " + stack + " matches " + pointers.size() + " count");
        for (Pointer pointer : pointers) {
            System.out.println("Stack matches: " + pointer);
        }
    }

    private void searchHeap(byte[] data, int prot) {
        if (data == null || data.length < 1) {
            System.err.println("search heap failed as empty data");
            return;
        }

        List<Pointer> list = new ArrayList<>();
        Unicorn unicorn = emulator.getUnicorn();
        for (MemoryMap map : emulator.getMemory().getMemoryMap()) {
            if ((map.prot & prot) != 0) {
                Collection<Pointer> pointers = searchMemory(unicorn, map.base, map.base + map.size, data);
                list.addAll(pointers);
            }
        }
        System.out.println("Search heap matches " + list.size() + " count");
        for (Pointer pointer : list) {
            System.out.println("Heap matches: " + pointer);
        }
    }

    private Collection<Pointer> searchMemory(Unicorn unicorn, long start, long end, byte[] data) {
        List<Pointer> pointers = new ArrayList<>();
        for (long i = start, m = end - data.length; i < m; i++) {
            byte[] oneByte = unicorn.mem_read(i, 1);
            if (data[0] != oneByte[0]) {
                continue;
            }

            if (Arrays.equals(data, unicorn.mem_read(i, data.length))) {
                pointers.add(UnicornPointer.pointer(emulator, i));
                i += (data.length - 1);
            }
        }
        return pointers;
    }

    final boolean handleCommon(Unicorn u, String line, long address, int size, long nextAddress) throws DecoderException {
        if ("c".equals(line)) { // continue
            return true;
        }
        if ("n".equals(line)) {
            if (nextAddress == 0) {
                System.out.println("Next address failed.");
                return false;
            } else {
                addBreakPoint(nextAddress).setTemporary(true);
                return true;
            }
        }
        if (line.startsWith("st")) { // search stack
            int index = line.indexOf(' ');
            if (index != -1) {
                String hex = line.substring(index + 1).trim();
                byte[] data = Hex.decodeHex(hex.toCharArray());
                if (data.length > 0) {
                    searchStack(data);
                    return false;
                }
            }
        }
        if (line.startsWith("shw")) { // search writable heap
            int index = line.indexOf(' ');
            if (index != -1) {
                String hex = line.substring(index + 1).trim();
                byte[] data = Hex.decodeHex(hex.toCharArray());
                if (data.length > 0) {
                    searchHeap(data, UnicornConst.UC_PROT_WRITE);
                    return false;
                }
            }
        }
        if (line.startsWith("shr")) { // search readable heap
            int index = line.indexOf(' ');
            if (index != -1) {
                String hex = line.substring(index + 1).trim();
                byte[] data = Hex.decodeHex(hex.toCharArray());
                if (data.length > 0) {
                    searchHeap(data, UnicornConst.UC_PROT_READ);
                    return false;
                }
            }
        }
        if (line.startsWith("shx")) { // search executable heap
            int index = line.indexOf(' ');
            if (index != -1) {
                String hex = line.substring(index + 1).trim();
                byte[] data = Hex.decodeHex(hex.toCharArray());
                if (data.length > 0) {
                    searchHeap(data, UnicornConst.UC_PROT_EXEC);
                    return false;
                }
            }
        }
        if (line.startsWith("vm")) {
            Memory memory = emulator.getMemory();
            String maxLengthSoName = memory.getMaxLengthLibraryName();
            StringBuilder sb = new StringBuilder();
            String filter = null;
            {
                int index = line.indexOf(' ');
                if (index != -1) {
                    filter = line.substring(index + 1).trim();
                }
            }
            int index = 0;
            for (Module module : memory.getLoadedModules()) {
                if (filter == null || module.name.contains(filter)) {
                    sb.append(String.format("[%2s][%" + maxLengthSoName.length() + "s] ", index++, FilenameUtils.getName(module.name)));
                    sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x-0x%x]", module.base, module.base + module.size));
                    sb.append(module.getPath());
                    sb.append("\n");
                }
            }
            System.out.println(sb);
            return false;
        }
        if ("stop".equals(line)) {
            u.emu_stop();
            return true;
        }
        if ("s".equals(line) || "si".equals(line)) {
            singleStep = 1;
            return true;
        }
        if (line.startsWith("s")) {
            try {
                singleStep = Integer.parseInt(line.substring(1));
                return true;
            } catch (NumberFormatException e) {
                breakMnemonic = line.substring(1);
                return true;
            }
        }
        if (line.startsWith("p")) {
            long originalAddress = address;
            String assembly = line.substring(1).trim();
            boolean isThumb = (address & 1) != 0;
            try (Keystone keystone = createKeystone(isThumb)) {
                KeystoneEncoded encoded = keystone.assemble(assembly);
                byte[] code = encoded.getMachineCode();
                address &= (~1);
                if (code.length != nextAddress - address) {
                    System.err.println("patch code failed: nextAddress=0x" + Long.toHexString(nextAddress) + ", codeSize=" + code.length);
                    return false;
                }
                Pointer pointer = UnicornPointer.pointer(emulator, address);
                assert pointer != null;
                pointer.write(0, code, 0, code.length);
                disassemble(emulator, originalAddress, size, isThumb);
                return true;
            } catch (AssembleFailedKeystoneException e) {
                System.err.println("Assemble failed: " + assembly);
                return false;
            }
        }

        showHelp();
        return false;
    }

    void showHelp() {}

    /**
     * @return next address
     */
    final long disassemble(Emulator<?> emulator, long address, int size, boolean thumb) {
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
            sb.append(ARM.assembleDetail(emulator, ins, history.address, history.thumb, on)).append('\n');
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
            sb.append(ARM.assembleDetail(emulator, ins, nextAddr, thumb, on)).append('\n');
            nextAddr += ins.size;
        }
        System.out.println(sb);
        return next;
    }

    final void disassembleBlock(Emulator<?> emulator, long address, boolean thumb) {
        StringBuilder sb = new StringBuilder();
        long nextAddr = address;
        UnicornPointer pointer = UnicornPointer.pointer(emulator, address);
        assert pointer != null;
        byte[] code = pointer.getByteArray(0, 4 * 10);
        Capstone.CsInsn[] insns = emulator.disassemble(nextAddr, code, thumb);
        for (Capstone.CsInsn ins : insns) {
            sb.append("    ");
            sb.append(ARM.assembleDetail(emulator, ins, nextAddr, thumb, false)).append('\n');
            nextAddr += ins.size;
        }
        System.out.println(sb);
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
                    public Number[] callFunction(Emulator<?> emulator, long offset, Object... args) {
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
                    public int callEntry(Emulator<?> emulator, String... args) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public String getPath() {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public void registerSymbol(String symbolName, long address) {
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
        if (breakPoint != null) {
            if (log.isDebugEnabled()) {
                log.debug(Inspector.inspectString(breakPoint.backup, "brk pc=" + pc + ", svcNumber=" + svcNumber + ", address=0x" + Long.toHexString(breakPoint.address)));
            }
            pc.write(0, breakPoint.backup, 0, breakPoint.backup.length);
        }

        BreakPointCallback callback = breakPoint == null ? null : breakPoint.callback;
        if (callback == null || callback.onHit(emulator, breakPoint.address)) {
            debug();
        }
    }

    @Override
    public void close() {
    }

}
