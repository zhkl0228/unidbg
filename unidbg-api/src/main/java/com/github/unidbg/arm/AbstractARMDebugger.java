package com.github.unidbg.arm;

import capstone.Capstone;
import com.github.unidbg.*;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.debugger.DebugListener;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.struct.StdString;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneEncoded;
import keystone.exceptions.AssembleFailedKeystoneException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class AbstractARMDebugger implements Debugger {

    private static final Log log = LogFactory.getLog(AbstractARMDebugger.class);

    private final Map<Long, BreakPoint> breakMap = new LinkedHashMap<>();

    protected final Emulator<?> emulator;

    protected AbstractARMDebugger(Emulator<?> emulator) {
        this.emulator = emulator;
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

    @Override
    public BreakPoint addBreakPoint(long address) {
        return addBreakPoint(address, null);
    }

    @Override
    public BreakPoint addBreakPoint(long address, BreakPointCallback callback) {
        boolean thumb = (address & 1) != 0;
        address &= (~1);

        if (log.isDebugEnabled()) {
            log.debug("addBreakPoint address=0x" + Long.toHexString(address));
        }
        BreakPoint breakPoint = emulator.getBackend().addBreakPoint(address, callback, thumb);
        breakMap.put(address, breakPoint);
        return breakPoint;
    }

    protected abstract Keystone createKeystone(boolean isThumb);

    public final boolean removeBreakPoint(long address) {
        address &= (~1);

        if (breakMap.containsKey(address)) {
            breakMap.remove(address);
            return emulator.getBackend().removeBreakPoint(address);
        } else {
            return false;
        }
    }

    private DebugListener listener;

    @Override
    public void setDebugListener(DebugListener listener) {
        this.listener = listener;
    }

    @Override
    public void onBreak(Backend backend, long address, int size, Object user) {
        BreakPoint breakPoint = breakMap.get(address);
        if (breakPoint != null && breakPoint.isTemporary()) {
            removeBreakPoint(address);
        }
        BreakPointCallback callback;
        if (breakPoint != null && (callback = breakPoint.getCallback()) != null && callback.onHit(emulator, address)) {
            return;
        }
        try {
            if (listener == null || listener.canDebug(emulator, new CodeHistory(address, size, ARM.isThumb(backend)))) {
                if (traceHook != null) {
                    traceHook.unhook();
                    traceHook = null;
                }
                debugging = true;
                loop(emulator, address, size, null);
            }
        } catch (Exception e) {
            log.warn("process loop failed", e);
        } finally {
            debugging = false;
        }
    }

    private boolean debugging;

    @Override
    public boolean isDebugging() {
        return debugging;
    }

    @Override
    public final void hook(Backend backend, long address, int size, Object user) {
        Emulator<?> emulator = (Emulator<?>) user;

        try {
            if (breakMnemonic != null) {
                CodeHistory history = new CodeHistory(address, size, ARM.isThumb(backend));
                Capstone.CsInsn ins = history.disassemble(emulator);
                if (ins != null && breakMnemonic.equals(ins.mnemonic)) {
                    breakMnemonic = null;
                    backend.setFastDebug(true);
                    debugging = true;
                    loop(emulator, address, size, null);
                }
            }
        } catch (Exception e) {
            log.warn("process hook failed", e);
        } finally {
            debugging = false;
        }
    }

    @Override
    public void debug() {
        Backend backend = emulator.getBackend();
        long address;
        if (emulator.is32Bit()) {
            address = backend.reg_read(ArmConst.UC_ARM_REG_PC).intValue() & 0xffffffffL;
        } else {
            address = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        }
        try {
            debugging = true;
            loop(emulator, address, 4, null);
        } catch (Exception e) {
            log.warn("debug failed", e);
        } finally {
            debugging = false;
        }
    }

    protected final void setSingleStep(int singleStep) {
        emulator.getBackend().setSingleStep(singleStep);
    }

    private String breakMnemonic;

    protected abstract void loop(Emulator<?> emulator, long address, int size, Callable<?> callable) throws Exception;

    protected boolean callbackRunning;

    @Override
    public <T> T run(Callable<T> callable) throws Exception {
        if (callable == null) {
            throw new NullPointerException();
        }
        T ret;
        try {
            callbackRunning = true;
            ret = callable.call();
        } finally {
            callbackRunning = false;
        }
        try {
            debugging = true;
            loop(emulator, 0, 0, callable);
        } finally {
            debugging = false;
        }
        return ret;
    }

    protected enum StringType {
        nullTerminated,
        std_string
    }

    final void dumpMemory(Pointer pointer, int _length, String label, StringType stringType) {
        if (stringType != null) {
            if (stringType == StringType.nullTerminated) {
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
            } else if (stringType == StringType.std_string) {
                StdString string = StdString.createStdString(emulator, pointer);
                long size = string.getDataSize();
                byte[] data = string.getData();
                Inspector.inspect(data, size >= 1024 ? (label + ", hex=" + Hex.encodeHexString(data)) : label);
            } else {
                throw new UnsupportedOperationException("stringType=" + stringType);
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
            } else if (_length == 16) {
                byte[] tmp = Arrays.copyOf(data, 16);
                for (int i = 0; i < 8; i++) {
                    byte b = tmp[i];
                    tmp[i] = tmp[15 - i];
                    tmp[15 - i] = b;
                }
                byte[] bytes = new byte[tmp.length + 1];
                System.arraycopy(tmp, 0, bytes, 1, tmp.length); // makePositive
                sb.append(", value=0x").append(new BigInteger(bytes).toString(16));
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

        UnidbgPointer stack = emulator.getContext().getStackPointer();
        Backend backend = emulator.getBackend();
        Collection<Pointer> pointers = searchMemory(backend, stack.toUIntPeer(), emulator.getMemory().getStackBase(), data);
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
        Backend backend = emulator.getBackend();
        for (MemoryMap map : emulator.getMemory().getMemoryMap()) {
            if ((map.prot & prot) != 0) {
                Collection<Pointer> pointers = searchMemory(backend, map.base, map.base + map.size, data);
                list.addAll(pointers);
            }
        }
        System.out.println("Search heap matches " + list.size() + " count");
        for (Pointer pointer : list) {
            System.out.println("Heap matches: " + pointer);
        }
    }

    private Collection<Pointer> searchMemory(Backend backend, long start, long end, byte[] data) {
        List<Pointer> pointers = new ArrayList<>();
        for (long i = start, m = end - data.length; i < m; i++) {
            byte[] oneByte = backend.mem_read(i, 1);
            if (data[0] != oneByte[0]) {
                continue;
            }

            if (Arrays.equals(data, backend.mem_read(i, data.length))) {
                pointers.add(UnidbgPointer.pointer(emulator, i));
                i += (data.length - 1);
            }
        }
        return pointers;
    }

    private Unicorn.UnHook traceHook;

    final boolean handleCommon(Backend backend, String line, long address, int size, long nextAddress, Callable<?> callable) throws Exception {
        if ("exit".equals(line) || "quit".equals(line)) { // continue
            return true;
        }
        if (callable == null || callbackRunning) {
            if ("c".equals(line)) { // continue
                return true;
            }
        } else {
            if ("c".equals(line)) {
                try {
                    callbackRunning = true;
                    callable.call();
                    return false;
                } finally {
                    callbackRunning = false;
                }
            }
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
        if (emulator.getFamily() == Family.iOS && !emulator.isRunning() && line.startsWith("dump ")) {
            String className = line.substring(5).trim();
            if (className.length() > 0) {
                dumpClass(className);
                return false;
            }
        }
        if (emulator.getFamily() == Family.iOS && !emulator.isRunning() && line.startsWith("search ")) {
            String keywords = line.substring(7).trim();
            if (keywords.length() > 0) {
                searchClass(keywords);
                return false;
            }
        }
        if (line.startsWith("trace")) { // start trace instructions
            Memory memory = emulator.getMemory();
            Pattern pattern = Pattern.compile("trace\\s+(\\d+)\\s+(\\d+)");
            Matcher matcher = pattern.matcher(line);
            AssemblyCodeDumper codeHook = new AssemblyCodeDumper(emulator);
            long begin, end;
            if (matcher.find()) {
                begin = Long.parseLong(matcher.group(1));
                end = Long.parseLong(matcher.group(2));
                System.out.println("Set trace begin->end instructions success.");
            } else {
                String redirect = null;
                Module module = memory.findModuleByAddress(address);
                {
                    int index = line.indexOf(' ');
                    if (index != -1) {
                        redirect = line.substring(index + 1).trim();
                    }
                }
                File traceFile = null;
                if (redirect != null && redirect.trim().length() > 0) {
                    Module check = memory.findModule(redirect);
                    if (check != null) {
                        module = check;
                    } else {
                        File outFile = new File(redirect.trim());
                        try {
                            if (!outFile.exists() && !outFile.createNewFile()) {
                                throw new IllegalStateException("createNewFile: " + outFile);
                            }
                            codeHook.setRedirect(new PrintStream(new FileOutputStream(outFile, true), false));
                            traceFile = outFile;
                        } catch (IOException e) {
                            System.err.println("Set trace redirect out file failed: " + outFile);
                            return false;
                        }
                    }
                }
                begin = module == null ? 1 : module.base;
                end = module == null ? 0 : (module.base + module.size);
                System.out.println("Set trace " + (module == null ? "all" : module) + " instructions success" + (traceFile == null ? "." : (" with trace file: " + traceFile)));
            }
            codeHook.initialize(begin, end, null);
            traceHook = emulator.getBackend().hook_add_new(codeHook, begin, end, emulator);
            return false;
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
            long filterAddress = -1;
            if (filter != null && filter.startsWith("0x")) {
                filterAddress = Long.parseLong(filter.substring(2), 16);
            }
            for (Module module : memory.getLoadedModules()) {
                if (filter == null || module.getPath().toLowerCase().contains(filter.toLowerCase()) || (filterAddress >= module.base && filterAddress < module.base + module.size)) {
                    sb.append(String.format("[%3s][%" + maxLengthSoName.length() + "s] ", index++, FilenameUtils.getName(module.name)));
                    sb.append(String.format("[0x%0" + Long.toHexString(memory.getMaxSizeOfLibrary()).length() + "x-0x%x]", module.getBaseHeader(), module.base + module.size));
                    sb.append(module.getPath());
                    sb.append("\n");
                }
            }
            if (index == 0) {
                System.err.println("Find loaded library failed with filter: " + filter);
            } else {
                System.out.println(sb);
            }
            return false;
        }
        if ("vbs".equals(line)) { // view breakpoints
            Memory memory = emulator.getMemory();
            StringBuilder sb = new StringBuilder("* means temporary bp:\n");
            String maxLengthSoName = memory.getMaxLengthLibraryName();
            for (Map.Entry<Long, BreakPoint> entry : breakMap.entrySet()) {
                address = entry.getKey();
                BreakPoint bp = entry.getValue();
                Capstone.CsInsn ins = null;
                try {
                    byte[] code = backend.mem_read(address, 4);
                    Capstone.CsInsn[] insns = emulator.disassemble(address, code, bp.isThumb(), 1);
                    if (insns != null && insns.length > 0) {
                        ins = insns[0];
                    }
                } catch(Exception ignored) {}

                if (ins == null) {
                    sb.append(String.format("[%" + String.valueOf(maxLengthSoName).length() + "s]", "0x" + Long.toHexString(address)));
                    if (bp.isTemporary()) {
                        sb.append('*');
                    }
                } else {
                    sb.append(ARM.assembleDetail(emulator, ins, address, bp.isThumb(), bp.isTemporary()));
                }
                sb.append("\n");
            }
            System.out.println(sb);
            return false;
        }
        if ("stop".equals(line)) {
            backend.emu_stop();
            return true;
        }
        if ("s".equals(line) || "si".equals(line)) {
            setSingleStep(1);
            return true;
        }
        if (line.startsWith("s")) {
            try {
                setSingleStep(Integer.parseInt(line.substring(1)));
                return true;
            } catch (NumberFormatException e) {
                breakMnemonic = line.substring(1);
                backend.setFastDebug(false);
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
                Pointer pointer = UnidbgPointer.pointer(emulator, address);
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

    protected void searchClass(String keywords) {
    }

    protected void dumpClass(String className) {
    }

    void showHelp() {}

    /**
     * @return next address
     */
    final long disassemble(Emulator<?> emulator, long address, int size, boolean thumb) {
        long next = 0;
        boolean on = false;
        StringBuilder sb = new StringBuilder();
        long nextAddr = address;
        for (CodeHistory history : Collections.singletonList(new CodeHistory(address, size, ARM.isThumb(emulator.getBackend())))) {
            Capstone.CsInsn ins = history.disassemble(emulator);
            if (ins == null) {
                nextAddr += size;
                continue;
            }
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
            sb.append(ARM.assembleDetail(emulator, ins, history.address, history.thumb, on)).append('\n');
            nextAddr += ins.bytes.length;
        }
        Capstone.CsInsn[] insns = emulator.disassemble(nextAddr, 4 * 15, 15);
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
        if (on) {
            next = nextAddr;
        }
        if (thumb) {
            next |= 1;
        }
        return next;
    }

    final void disassembleBlock(Emulator<?> emulator, long address, boolean thumb) {
        StringBuilder sb = new StringBuilder();
        long nextAddr = address;
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, address);
        assert pointer != null;
        byte[] code = pointer.getByteArray(0, 4 * 10);
        Capstone.CsInsn[] insns = emulator.disassemble(nextAddr, code, thumb, 0);
        for (Capstone.CsInsn ins : insns) {
            sb.append("    ");
            sb.append(ARM.assembleDetail(emulator, ins, nextAddr, thumb, false)).append('\n');
            nextAddr += ins.size;
        }
        System.out.println(sb);
    }

    public static Module findModuleByAddress(Emulator<?> emulator, long address) {
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
        debug();
    }

    @Override
    public void close() {
    }

}
