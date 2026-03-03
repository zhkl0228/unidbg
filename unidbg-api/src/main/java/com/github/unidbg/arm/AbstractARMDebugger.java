package com.github.unidbg.arm;

import capstone.api.Instruction;
import capstone.api.RegsAccess;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.*;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.debugger.*;
import com.github.unidbg.mcp.McpServer;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.RunnableTask;
import com.github.unidbg.thread.Task;
import com.github.unidbg.unix.struct.StdString;
import com.github.unidbg.unwind.Unwinder;
import com.github.unidbg.utils.Inspector;
import com.github.zhkl0228.demumble.DemanglerFactory;
import com.github.zhkl0228.demumble.GccDemangler;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneEncoded;
import keystone.exceptions.AssembleFailedKeystoneException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.UnicornConst;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class AbstractARMDebugger implements Debugger {

    private static final Logger log = LoggerFactory.getLogger(AbstractARMDebugger.class);

    private final Map<Long, BreakPoint> breakMap = new LinkedHashMap<>();

    @Override
    public Map<Long, BreakPoint> getBreakPoints() {
        return breakMap;
    }

    protected final Emulator<?> emulator;
    protected McpServer mcpServer;
    protected volatile boolean scannerNeedsRefresh;

    protected AbstractARMDebugger(Emulator<?> emulator) {
        this.emulator = emulator;
    }

    private final List<UnHook> unHookList = new ArrayList<>();

    @Override
    public void onAttach(UnHook unHook) {
        unHookList.add(unHook);
    }

    @Override
    public void detach() {
        for (Iterator<UnHook> iterator = unHookList.iterator(); iterator.hasNext(); ) {
            iterator.next().unhook();
            iterator.remove();
        }
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
            log.debug("addBreakPoint address=0x{}", Long.toHexString(address));
        }
        BreakPoint breakPoint = emulator.getBackend().addBreakPoint(address, callback, thumb);
        breakMap.put(address, breakPoint);
        return breakPoint;
    }

    @Override
    public void traceFunctionCall(FunctionCallListener listener) {
        traceFunctionCall(null, listener);
    }

    @Override
    public void traceFunctionCall(Module module, FunctionCallListener listener) {
        throw new UnsupportedOperationException();
    }

    protected abstract Keystone createKeystone(boolean isThumb);

    protected abstract int resolveRegister(String command, String[] nameOut);

    protected abstract int resolveWriteRegister(String command);

    protected abstract void showWriteRegs(int reg);

    protected abstract void showWriteHelp();

    final boolean handleWriteCommand(Backend backend, String line) {
        if (!line.startsWith("w") || "where".equals(line)) {
            return false;
        }
        String command;
        String[] tokens = line.split("\\s+");
        if (tokens.length < 2) {
            showWriteHelp();
            return true;
        }
        long value;
        try {
            command = tokens[0];
            String str = tokens[1];
            value = Utils.parseNumber(str);
        } catch (NumberFormatException e) {
            e.printStackTrace(System.err);
            return true;
        }

        int reg = resolveWriteRegister(command);
        if (reg != -1) {
            backend.reg_write(reg, value);
            showWriteRegs(reg);
            return true;
        }

        if (command.startsWith("wb0x") || command.startsWith("ws0x") || command.startsWith("wi0x") || command.startsWith("wl0x")) {
            String hex = command.substring(4).trim();
            if (hex.endsWith("L")) {
                hex = hex.substring(0, hex.length() - 1);
            }
            long addr = Long.parseLong(hex, 16);
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
            return true;
        }
        return false;
    }

    final boolean handleMemoryCommand(String line) {
        if (!line.startsWith("m")) {
            return false;
        }
        String command = line;
        String[] tokens = line.split("\\s+");
        int length = 0x70;
        try {
            if (tokens.length >= 2) {
                command = tokens[0];
                String str = tokens[1];
                length = (int) Utils.parseNumber(str);
            }
        } catch(NumberFormatException ignored) {}
        StringType stringType = null;
        if (command.endsWith("objc")) {
            stringType = StringType.objc_object;
            command = command.substring(0, command.length() - 4);
        } else if (command.endsWith("std")) {
            stringType = StringType.std_string;
            command = command.substring(0, command.length() - 3);
        } else if (command.endsWith("s")) {
            stringType = StringType.nullTerminated;
            command = command.substring(0, command.length() - 1);
        }

        if (command.startsWith("m0x")) {
            String hex = command.substring(3).trim();
            if (hex.endsWith("L")) {
                hex = hex.substring(0, hex.length() - 1);
            }
            long addr = Long.parseLong(hex, 16);
            Pointer pointer = UnidbgPointer.pointer(emulator, addr);
            if (pointer != null) {
                dumpMemory(pointer, length, pointer.toString(), stringType);
            } else {
                System.out.println(addr + " is null");
            }
            return true;
        }

        String[] nameOut = new String[1];
        int reg = resolveRegister(command, nameOut);
        if (reg != -1) {
            Pointer pointer = UnidbgPointer.register(emulator, reg);
            if (pointer != null) {
                dumpMemory(pointer, length, nameOut[0] + "=" + pointer, stringType);
            } else {
                System.out.println(nameOut[0] + " is null");
            }
            return true;
        }
        return false;
    }

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
                notifyBreakpointHit(address);
                cancelTrace();
                debugging = true;
                if (mcpServer != null) mcpServer.setDebugIdle(true);
                loop(emulator, address, size, null);
            }
        } catch (Exception e) {
            log.warn("process loop failed", e);
        } finally {
            if (mcpServer != null) mcpServer.setDebugIdle(false);
            debugging = false;
        }
    }

    private void cancelTrace() {
        if (traceHook != null) {
            traceHook.detach();
            traceHook = null;
        }
        if (traceHookRedirectStream != null) {
            com.alibaba.fastjson.util.IOUtils.close(traceHookRedirectStream);
            traceHookRedirectStream = null;
        }
        if (traceRead != null) {
            traceRead.detach();
            traceRead = null;
        }
        if (traceReadRedirectStream != null) {
            com.alibaba.fastjson.util.IOUtils.close(traceReadRedirectStream);
            traceReadRedirectStream = null;
        }
        if (traceWrite != null) {
            traceWrite.detach();
            traceWrite = null;
        }
        if (traceWriteRedirectStream != null) {
            com.alibaba.fastjson.util.IOUtils.close(traceWriteRedirectStream);
            traceWriteRedirectStream = null;
        }
    }

    private boolean debugging;

    @Override
    public boolean isDebugging() {
        return debugging;
    }

    private boolean blockHooked;
    private boolean breakNextBlock;

    @Override
    public void hookBlock(Backend backend, long address, int size, Object user) {
        if (breakNextBlock) {
            onBreak(backend, address, size, user);
            breakNextBlock = false;
        }
    }

    @Override
    public final void hook(Backend backend, long address, int size, Object user) {
        Emulator<?> emulator = (Emulator<?>) user;

        try {
            if (breakMnemonic != null) {
                CodeHistory history = new CodeHistory(address, size, ARM.isThumb(backend));
                Instruction[] instructions = history.disassemble(emulator);
                if (instructions.length > 0 && breakMnemonic.equals(instructions[0].getMnemonic())) {
                    breakMnemonic = null;
                    backend.setFastDebug(true);
                    cancelTrace();
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
    public void debug(String reason) {
        Backend backend = emulator.getBackend();
        long address;
        if (emulator.is32Bit()) {
            address = backend.reg_read(ArmConst.UC_ARM_REG_PC).intValue() & 0xffffffffL;
        } else {
            address = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        }
        notifyBreakpointHit(address, reason);
        try {
            cancelTrace();
            debugging = true;
            if (mcpServer != null) mcpServer.setDebugIdle(true);
            loop(emulator, address, 4, null);
        } catch (Exception e) {
            log.warn("debug failed", e);
        } finally {
            if (mcpServer != null) mcpServer.setDebugIdle(false);
            debugging = false;
        }
    }

    protected final void setSingleStep(int singleStep) {
        emulator.getBackend().setSingleStep(singleStep);
    }

    private String breakMnemonic;

    protected abstract void loop(Emulator<?> emulator, long address, int size, DebugRunnable<?> runnable) throws Exception;

    protected boolean callbackRunning;
    private volatile DebugRunnable<?> currentRunnable;

    @Override
    public boolean hasRunnable() {
        return currentRunnable != null;
    }

    @Override
    public <T> T run(DebugRunnable<T> runnable) throws Exception {
        if (runnable == null) {
            throw new NullPointerException();
        }
        currentRunnable = runnable;
        T ret;
        try {
            callbackRunning = true;
            if (mcpServer != null) mcpServer.setDebugIdle(false);
            ret = runnable.runWithArgs(null);
        } finally {
            callbackRunning = false;
        }
        try {
            cancelTrace();
            debugging = true;
            if (mcpServer != null) mcpServer.setDebugIdle(true);
            loop(emulator, -1, 0, runnable);
        } finally {
            if (mcpServer != null) mcpServer.setDebugIdle(false);
            debugging = false;
        }
        return ret;
    }

    protected enum StringType {
        nullTerminated,
        std_string,
        objc_object
    }

    final void dumpMemory(Pointer pointer, int _length, String label, StringType stringType) {
        if (stringType != null) {
            if (stringType == StringType.nullTerminated) {
                long addr = 0;
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                boolean foundTerminated = false;
                while (true) {
                    byte[] data = pointer.getByteArray(addr, 0x10);
                    int length = Utils.indexOfNullTerminator(data);
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
                    Inspector.inspect(baos.toByteArray(), baos.size() >= 1024 ? (label + ", hex=" + Hex.encodeHexString(baos.toByteArray())) : (label + ", str=" + new String(baos.toByteArray(), StandardCharsets.UTF_8)));
                } else {
                    Inspector.inspect(pointer.getByteArray(0, _length), label + ", find NULL-terminated failed");
                }
            } else if (stringType == StringType.std_string) {
                StdString string = StdString.createStdString(emulator, pointer);
                long size = string.getDataSize();
                byte[] data = string.getData(emulator);
                Inspector.inspect(data, size >= 1024 ? (label + ", hex=" + Hex.encodeHexString(data) + ", std=" + new String(data, StandardCharsets.UTF_8)) : label);
            } else if (stringType == StringType.objc_object) {
                long addr = ((UnidbgPointer) pointer).peer;
                try {
                    String className = emulator.getObjcClassName(addr);
                    if (className != null) {
                        System.out.println(label + " -> ObjC class: " + className);
                    } else {
                        System.out.println(label + " -> ObjC class name not resolved");
                    }
                } catch (UnsupportedOperationException e) {
                    System.out.println(label + " -> " + e.getMessage());
                } catch (Exception e) {
                    System.out.println(label + " -> failed to read ObjC class: " + e);
                }
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
                sb.append(", value=0x").append(ARM.newBigInteger(Arrays.copyOf(data, 0x10)).toString(16));
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
        Collection<Pointer> pointers = searchMemory(backend, stack.peer, emulator.getMemory().getStackBase(), data);
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

    private AssemblyCodeDumper traceHook;
    private PrintStream traceHookRedirectStream;
    private TraceMemoryHook traceRead;
    private PrintStream traceReadRedirectStream;
    private TraceMemoryHook traceWrite;
    private PrintStream traceWriteRedirectStream;

    private void setupTraceMemory(Backend backend, String line, boolean isRead, int traceSize) throws IOException {
        String type = isRead ? "Read" : "Write";
        String typeLower = isRead ? "read" : "write";
        Pattern pattern = Pattern.compile("trace" + type + "\\s+(\\w+)\\s+(\\w+)");
        Matcher matcher = pattern.matcher(line);
        TraceMemoryHook existingHook = isRead ? traceRead : traceWrite;
        if (existingHook != null) {
            existingHook.detach();
        }
        TraceMemoryHook hook = new TraceMemoryHook(isRead);
        long begin, end;
        if (matcher.find()) {
            begin = Utils.parseNumber(matcher.group(1));
            end = Utils.parseNumber(matcher.group(2));
            if (begin > end && end > 0 && end <= traceSize) {
                end += begin;
            }
        } else {
            begin = 1;
            end = 0;
        }
        PrintStream redirectStream = null;
        if (begin >= end) {
            File traceFile = new File("target/trace" + type + ".txt");
            if (!traceFile.exists() && !traceFile.createNewFile()) {
                throw new IllegalStateException("createNewFile: " + traceFile);
            }
            redirectStream = new PrintStream(new BufferedOutputStream(Files.newOutputStream(traceFile.toPath())), true);
            redirectStream.printf("[%s]Start trace%s%n", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()), type);
            hook.setRedirect(redirectStream);
            System.out.printf("Set trace all memory %s success with trace file: %s.%n", typeLower, traceFile.getAbsolutePath());
        } else {
            boolean needTraceFile = end - begin > traceSize;
            if (needTraceFile) {
                File traceFile = new File(String.format("target/trace%s_0x%x-0x%x.txt", type, begin, end));
                if (!traceFile.exists() && !traceFile.createNewFile()) {
                    throw new IllegalStateException("createNewFile: " + traceFile);
                }
                redirectStream = new PrintStream(new BufferedOutputStream(Files.newOutputStream(traceFile.toPath())), true);
                redirectStream.printf("[%s]Start trace%s: 0x%x-0x%x%n", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()), type, begin, end);
                hook.setRedirect(redirectStream);
                System.out.printf("Set trace 0x%x->0x%x memory %s success with trace file: %s.%n", begin, end, typeLower, traceFile.getAbsolutePath());
            } else {
                System.out.printf("Set trace 0x%x->0x%x memory %s success.%n", begin, end, typeLower);
            }
        }
        if (isRead) {
            traceRead = hook;
            traceReadRedirectStream = redirectStream;
            backend.hook_add_new((ReadHook) hook, begin, end, emulator);
        } else {
            traceWrite = hook;
            traceWriteRedirectStream = redirectStream;
            backend.hook_add_new((WriteHook) hook, begin, end, emulator);
        }
    }

    final boolean handleCommon(Backend backend, String line, long address, int size, long nextAddress, DebugRunnable<?> runnable) throws Exception {
        if ("help".equals(line)) {
            showHelp(address);
            return false;
        }
        if (handleMemoryCommand(line)) {
            return false;
        }
        if ("where".equals(line)) {
            new Exception("here").printStackTrace(System.out);
            return false;
        }
        if (line.startsWith("wx0x")) {
            String[] tokens = line.split("\\s+");
            String hex = tokens[0].substring(4).trim();
            if (hex.endsWith("L")) {
                hex = hex.substring(0, hex.length() - 1);
            }
            long addr = Long.parseLong(hex, 16);
            Pointer pointer = UnidbgPointer.pointer(emulator, addr);
            if (pointer != null && tokens.length > 1) {
                byte[] data = Hex.decodeHex(tokens[1].toCharArray());
                pointer.write(0, data, 0, data.length);
                dumpMemory(pointer, data.length, pointer.toString(), null);
            } else {
                System.out.println(addr + " is null");
            }
            return false;
        }
        if (emulator.isRunning() && "bt".equals(line)) {
            try {
                emulator.getUnwinder().unwind();
            } catch (Throwable e) {
                e.printStackTrace(System.err);
            }
            return false;
        }
        if (handleBreakpointCommand(line, address)) {
            return false;
        }
        switch (line) {
            case "blr": {
                long addr = emulator.is32Bit()
                        ? backend.reg_read(ArmConst.UC_ARM_REG_LR).intValue() & 0xffffffffL
                        : backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
                addAndPrintBreakPoint(addr);
                return false;
            }
            case "r": {
                long addr = emulator.is32Bit()
                        ? backend.reg_read(ArmConst.UC_ARM_REG_PC).intValue() & 0xffffffffL
                        : backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                if (removeBreakPoint(addr)) {
                    Module module = findModuleByAddress(emulator, addr);
                    System.out.println("Remove breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
                }
                return false;
            }
            case "b": {
                long addr = emulator.is32Bit()
                        ? backend.reg_read(ArmConst.UC_ARM_REG_PC).intValue() & 0xffffffffL
                        : backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                addAndPrintBreakPoint(addr);
                return false;
            }
        }
        if (line.startsWith("run") && runnable != null) {
            String arg = line.substring(3).trim();
            try {
                callbackRunning = true;
                if (mcpServer != null) mcpServer.setDebugIdle(false);
                if (!arg.isEmpty()) {
                    String[] args = arg.split("\\s+");
                    runnable.runWithArgs(args);
                } else {
                    runnable.runWithArgs(null);
                }
                notifyExecutionCompleted();
            } catch (Exception e) {
                log.warn("runWithArgs failed: arg={}", arg, e);
                notifyExecutionError(e);
            } finally {
                callbackRunning = false;
                if (mcpServer != null) mcpServer.setDebugIdle(true);
            }
            return false;
        }
        switch (line) {
            case "exit":
            case "quit":
            case "q":  // continue
                return true;
            case "gc":
                System.out.println("Run System.gc();");
                System.gc();
                return false;
            case "threads":
                for (Task task : emulator.getThreadDispatcher().getTaskList()) {
                    System.out.println(task.getId() + ": " + task);
                }
                return false;
        }
        if (line.startsWith("mcp")) {
            startMcpServer(line);
            return false;
        }
        if ("_mcp".equals(line)) {
            if (mcpServer != null) {
                mcpServer.executePendingOperation();
            }
            return false;
        }
        if (runnable == null || callbackRunning) {
            if ("c".equals(line)) { // continue
                return true;
            }
        } else {
            if ("c".equals(line)) {
                try {
                    callbackRunning = true;
                    if (mcpServer != null) mcpServer.setDebugIdle(false);
                    runnable.runWithArgs(null);
                    cancelTrace();
                    notifyExecutionCompleted();
                    return false;
                } finally {
                    callbackRunning = false;
                    if (mcpServer != null) mcpServer.setDebugIdle(true);
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
            if (!className.isEmpty()) {
                dumpClass(className);
                return false;
            }
        }
        if (emulator.getFamily() == Family.iOS && !emulator.isRunning() && line.startsWith("gpb ")) {
            String className = line.substring(4).trim();
            if (!className.isEmpty()) {
                dumpGPBProtobufMsg(className);
                return false;
            }
        }
        if (emulator.getFamily() == Family.iOS && !emulator.isRunning() && line.startsWith("search ")) {
            String keywords = line.substring(7).trim();
            if (!keywords.isEmpty()) {
                searchClass(keywords);
                return false;
            }
        }
        int traceSize = 0x10000;
        if (line.startsWith("traceRead")) { // start trace memory read
            setupTraceMemory(backend, line, true, traceSize);
            return false;
        }
        if (line.startsWith("traceWrite")) { // start trace memory write
            setupTraceMemory(backend, line, false, traceSize);
            return false;
        }
        if ("traceAll".equals(line)) {
            line = "trace 1 0";
        }
        if (line.startsWith("trace")) { // start trace instructions
            Memory memory = emulator.getMemory();
            Pattern pattern = Pattern.compile("trace\\s+(\\w+)\\s+(\\w+)");
            Matcher matcher = pattern.matcher(line);
            if (traceHook != null) {
                traceHook.detach();
            }
            traceHookRedirectStream = null;
            long begin, end;
            if (matcher.find()) {
                begin = Utils.parseNumber(matcher.group(1));
                end = Utils.parseNumber(matcher.group(2));
                if (begin > end && end > 0 && end < traceSize) {
                    end += begin;
                }
                if (begin >= end) {
                    File traceFile = new File("target/traceCode.txt");
                    if (!traceFile.exists() && (!traceFile.getParentFile().exists() || !traceFile.createNewFile())) {
                        throw new IllegalStateException("createNewFile: " + traceFile.getAbsolutePath());
                    }
                    traceHookRedirectStream = new PrintStream(new BufferedOutputStream(Files.newOutputStream(traceFile.toPath())), true);
                    traceHookRedirectStream.printf("[%s]Start traceCode%n", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
                    System.out.printf("Set trace all instructions success with trace file: %s.%n", traceFile.getAbsolutePath());
                } else {
                    boolean needTraceFile = end - begin > traceSize;
                    if (needTraceFile) {
                        File traceFile = new File(String.format("target/traceCode_0x%x-0x%x.txt", begin, end));
                        if (!traceFile.exists() && !traceFile.createNewFile()) {
                            throw new IllegalStateException("createNewFile: " + traceFile);
                        }
                        traceHookRedirectStream = new PrintStream(new BufferedOutputStream(Files.newOutputStream(traceFile.toPath())), true);
                        traceHookRedirectStream.printf("[%s]Start traceCode: 0x%x-0x%x%n", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()), begin, end);
                        System.out.printf("Set trace 0x%x->0x%x instructions success with trace file: %s.%n", begin, end, traceFile.getAbsolutePath());
                    } else {
                        System.out.printf("Set trace 0x%x->0x%x instructions success.%n", begin, end);
                    }
                }
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
                if (redirect != null && !redirect.trim().isEmpty()) {
                    Module check = memory.findModule(redirect);
                    if (check != null) {
                        module = check;
                    } else {
                        File outFile = new File(redirect.trim());
                        try {
                            if (!outFile.exists() && !outFile.createNewFile()) {
                                throw new IllegalStateException("createNewFile: " + outFile);
                            }
                            traceHookRedirectStream = new PrintStream(new BufferedOutputStream(Files.newOutputStream(outFile.toPath())), true);
                            traceHookRedirectStream.printf("[%s]Start trace %s%n", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()), module == null ? "all" : module);
                            traceFile = outFile;
                        } catch (IOException e) {
                            System.err.println("Set trace redirect out file failed: " + outFile);
                            return false;
                        }
                    }
                }
                begin = module == null ? 1 : module.base;
                end = module == null ? 0 : (module.base + module.size);
                System.out.println("Set trace " + (module == null ? "all" : module) + " instructions success" + (traceFile == null ? "." : (" with trace file: " + traceFile.getAbsolutePath())));
            }
            traceHook = new AssemblyCodeDumper(emulator, begin, end, null);
            if (traceHookRedirectStream != null) {
                traceHook.setRedirect(traceHookRedirectStream);
            }
            backend.hook_add_new(traceHook, begin, end, emulator);
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
                filterAddress = Utils.parseNumber(filter);
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
        switch (line) {
            case "vbs":  // view breakpoints
                Memory memory = emulator.getMemory();
                StringBuilder sb = new StringBuilder("* means temporary bp:\n");
                String maxLengthSoName = memory.getMaxLengthLibraryName();
                for (Map.Entry<Long, BreakPoint> entry : breakMap.entrySet()) {
                    address = entry.getKey();
                    BreakPoint bp = entry.getValue();
                    Instruction ins = null;
                    try {
                        byte[] code = backend.mem_read(address, 4);
                        Instruction[] insns = emulator.disassemble(address, code, bp.isThumb(), 1);
                        if (insns != null && insns.length > 0) {
                            ins = insns[0];
                        }
                    } catch (Exception ignored) {
                    }

                    if (ins == null) {
                        sb.append(String.format("[%" + String.valueOf(maxLengthSoName).length() + "s]", "0x" + Long.toHexString(address)));
                        if (bp.isTemporary()) {
                            sb.append('*');
                        }
                    } else {
                        sb.append(ARM.assembleDetail(emulator, ins, address, bp.isThumb(), bp.isTemporary(), memory.getMaxLengthLibraryName().length()));
                    }
                    sb.append("\n");
                }
                System.out.println(sb);
                return false;
            case "stop":
                backend.emu_stop();
                return true;
            case "s":
            case "si":
                setSingleStep(1);
                return true;
            case "nb":
                if (!blockHooked) {
                    blockHooked = true;
                    emulator.getBackend().hook_add_new((BlockHook) this, 1, 0, emulator);
                }
                breakNextBlock = true;
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
            boolean isThumb = ARM.isThumb(backend);
            try (Keystone keystone = createKeystone(isThumb)) {
                KeystoneEncoded encoded = keystone.assemble(assembly);
                byte[] code = encoded.getMachineCode();
                address &= (~1);
                if (code.length != (nextAddress & ~1) - address) {
                    System.err.println("patch code failed: nextAddress=0x" + Long.toHexString(nextAddress) + ", codeSize=" + code.length);
                    return false;
                }
                Pointer pointer = UnidbgPointer.pointer(emulator, address);
                assert pointer != null;
                pointer.write(0, code, 0, code.length);
                disassemble(emulator, originalAddress, size, isThumb);
                return false;
            } catch (AssembleFailedKeystoneException e) {
                System.err.println("Assemble failed: " + assembly);
                return false;
            }
        }
        Module module = emulator.getMemory().findModuleByAddress(address);
        if (module != null && line.startsWith("cc")) {
            int sizeBytes = (int) Utils.parseNumber(line.substring(2).trim()) & ~1;
            if (sizeBytes >= 2) {
                Instruction[] insns = emulator.disassemble(address & ~1, sizeBytes, Short.MAX_VALUE);
                StringBuilder sb = new StringBuilder();
                if (emulator.is32Bit()) {
                    sb.append("    \"").append("push {r7, lr}").append("\\n").append('"').append("\n\n");
                } else {
                    sb.append("    \"").append("sub sp, sp, #0x10").append("\\n").append('"').append('\n');
                    sb.append("    \"").append("stp x29, x30, [sp]").append("\\n").append('"').append("\n\n");
                }
                String lastRegWrite = null;
                for (Instruction insn : insns) {
                    RegsAccess regsAccess = insn.regsAccess();
                    short[] regsWrite;
                    if (regsAccess != null && (regsWrite = regsAccess.getRegsWrite()) != null && regsWrite.length == 1) {
                        lastRegWrite = insn.regName(regsWrite[0]);
                    }
                    String asm = "    \"" + insn + "\\n\"";
                    sb.append(String.format("%-50s", asm));
                    sb.append(" // 0x").append(Long.toHexString(insn.getAddress()));
                    sb.append(" offset 0x").append(Long.toHexString(insn.getAddress() - (address & ~1)));
                    sb.append("\n");
                }
                sb.append('\n');

                if (emulator.is32Bit()) {
                    if (lastRegWrite != null && !"r0".equals(lastRegWrite)) {
                        sb.append("    \"").append("mov r0, ").append(lastRegWrite).append("\\n").append('"').append('\n');
                    }
                    sb.append("    \"").append("pop {r7, pc}").append("\\n").append('"');
                } else {
                    if (lastRegWrite != null && !"x0".equals(lastRegWrite) && !"w0".equals(lastRegWrite)) {
                        sb.append("    \"").append("mov ").append(lastRegWrite.startsWith("x") ? "x0" : "w0").append(", ").append(lastRegWrite).append("\\n").append('"').append('\n');
                    }
                    sb.append("    \"").append("ldp x29, x30, [sp]").append("\\n").append('"').append('\n');
                    sb.append("    \"").append("add sp, sp, #0x10").append("\\n").append('"').append('\n');
                    sb.append("    \"").append("ret").append("\\n").append('"');
                }
                try(InputStream inputStream = Objects.requireNonNull(getClass().getResourceAsStream("/cc.c"))) {
                    String template = IOUtils.toString(inputStream, StandardCharsets.UTF_8);
                    if (emulator.is64Bit()) {
                        template = template.replace("$(ARCH_SPEC)", "-m64 -arch arm64");
                    } else {
                        template = template.replace("$(ARCH_SPEC)", "-m32 -arch armv7");
                    }
                    System.err.println(template.replace("$(REPLACE_ASM)", sb.toString()));
                }
            } else {
                System.err.println("Usage: cc (size bytes)");
            }
            return false;
        }

        showHelp(address);
        return false;
    }

    protected void dumpGPBProtobufMsg(String className) {
        throw new UnsupportedOperationException();
    }

    protected void searchClass(String keywords) {
    }

    protected void dumpClass(String className) {
    }

    final boolean handleBreakpointCommand(String line, long currentAddress) {
        if (!line.startsWith("b0x")) {
            return false;
        }
        try {
            if (line.endsWith("L")) {
                line = line.substring(0, line.length() - 1);
            }
            long addr = Long.parseLong(line.substring(3), 16) & (emulator.is32Bit() ? 0xffffffffL : 0xfffffffffffffffeL);
            Module module = null;
            if (addr < Memory.MMAP_BASE && (module = findModuleByAddress(emulator, currentAddress)) != null) {
                addr += module.base;
            }
            addBreakPoint(addr);
            if (module == null) {
                module = findModuleByAddress(emulator, addr);
            }
            System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
            return true;
        } catch (NumberFormatException ignored) {
        }
        return false;
    }

    private void addAndPrintBreakPoint(long addr) {
        addBreakPoint(addr);
        Module module = findModuleByAddress(emulator, addr);
        System.out.println("Add breakpoint: 0x" + Long.toHexString(addr) + (module == null ? "" : (" in " + module.name + " [0x" + Long.toHexString(addr - module.base) + "]")));
    }

    void showHelp(long address) {
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
        System.out.println("nb: break at next block");
        System.out.println("s|si: step into");
        System.out.println("s[decimal]: execute specified amount instruction");
    }

    final void showCommonHelp(long address) {
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
        System.out.println("traceRead [begin end]: Set trace memory read");
        System.out.println("traceWrite [begin end]: Set trace memory write");
        System.out.println("vm: view loaded modules");
        System.out.println("vbs: view breakpoints");
        System.out.println("d|dis: show disassemble");
        System.out.println("d(0x): show disassemble at specify address");
        System.out.println("stop: stop emulation");
        System.out.println("run [arg]: run test");
        System.out.println("gc: Run System.gc()");
        System.out.println("threads: show thread list");
        System.out.println("mcp [port]: start MCP server for AI tool integration (default port 9239)");

        if (emulator.getFamily() == Family.iOS && !emulator.isRunning()) {
            System.out.println("dump [class name]: dump objc class");
            System.out.println("search [keywords]: search objc classes");
            if (emulator.is64Bit()) {
                System.out.println("gpb [class name]: dump GPB protobuf msg def");
            }
        }

        Module module = emulator.getMemory().findModuleByAddress(address);
        if (module != null) {
            if (emulator.is32Bit()) {
                System.out.printf("cc size: convert asm from 0x%x - 0x%x + size bytes to c function%n", address, address);
            } else {
                System.out.printf("cc (size): convert asm from (0x%x) to (0x%x + size) bytes to c function%n", address, address);
            }
        }
    }

    private void appendSymbolInfo(StringBuilder sb, Emulator<?> emulator, long address) {
        Module module = findModuleByAddress(emulator, address);
        Symbol symbol = module == null ? null : module.findClosestSymbolByAddress(address, false);
        if (symbol != null && address - symbol.getAddress() <= Unwinder.SYMBOL_SIZE) {
            GccDemangler demangler = DemanglerFactory.createDemangler();
            sb.append(demangler.demangle(symbol.getName())).append(" + 0x").append(Long.toHexString(address - (symbol.getAddress() & ~1))).append("\n");
        }
    }

    /**
     * @return next address
     */
    final long disassemble(Emulator<?> emulator, long address, int size, boolean thumb) {
        long next = 0;
        boolean on = false;
        int maxLength = emulator.getMemory().getMaxLengthLibraryName().length();
        StringBuilder sb = new StringBuilder();
        appendSymbolInfo(sb, emulator, address);
        long nextAddr = address - size;
        for (CodeHistory history : Arrays.asList(
                new CodeHistory(address - size, size, thumb),
                new CodeHistory(address, size, thumb))
        ) {
            Instruction[] instructions = history.disassemble(emulator);
            if (instructions != null) {
                for (Instruction ins : instructions) {
                    if (ins.getAddress() == address) {
                        sb.append("=> *");
                        on = true;
                    } else {
                        sb.append("    ");
                        if (on) {
                            next = ins.getAddress();
                            on = false;
                        }
                    }
                    sb.append(ARM.assembleDetail(emulator, ins, ins.getAddress(), history.thumb, on, maxLength)).append('\n');
                    nextAddr += ins.getBytes().length;
                }
            }
        }
        Instruction[] insns = emulator.disassemble(nextAddr, 4 * 15, 15);
        if (insns != null) {
            for (Instruction ins : insns) {
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
                sb.append(ARM.assembleDetail(emulator, ins, nextAddr, thumb, on, maxLength)).append('\n');
                nextAddr += ins.getSize();
            }
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

    @Override
    public final void disassembleBlock(Emulator<?> emulator, long address, boolean thumb) {
        StringBuilder sb = new StringBuilder();
        appendSymbolInfo(sb, emulator, address);
        long nextAddr = address;
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, address);
        assert pointer != null;
        byte[] code = pointer.getByteArray(0, 4 * 10);
        Instruction[] insns = emulator.disassemble(nextAddr, code, thumb, 0);
        for (Instruction ins : insns) {
            sb.append("    ");
            sb.append(ARM.assembleDetail(emulator, ins, nextAddr, thumb, false, emulator.getMemory().getMaxLengthLibraryName().length())).append('\n');
            nextAddr += ins.getSize();
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
                module = new Module(name, region.begin, region.end - region.begin, Collections.emptyMap(), Collections.emptyList(), null) {
                    @Override
                    public Number callFunction(Emulator<?> emulator, long offset, Object... args) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public Symbol findSymbolByName(String name, boolean withDependencies) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public Symbol findClosestSymbolByAddress(long address, boolean fast) {
                        return null;
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
                    @Override
                    public int virtualMemoryAddressToFileOffset(long offset) {
                        throw new UnsupportedOperationException();
                    }
                };
            }
        }
        return module;
    }

    @Override
    public final void brk(UnidbgPointer pc, int svcNumber) {
        if (pc != null) {
            removeBreakPoint(pc.peer);
        }
        debug();
    }

    @Override
    public void addMcpTool(String name, String description, String... paramNames) {
        if (mcpServer != null) {
            mcpServer.addCustomTool(name, description, paramNames);
        } else {
            pendingMcpTools.add(new PendingMcpTool(name, description, paramNames));
        }
    }

    private final List<PendingMcpTool> pendingMcpTools = new ArrayList<>();

    private static class PendingMcpTool {
        final String name, description;
        final String[] paramNames;
        PendingMcpTool(String name, String description, String[] paramNames) {
            this.name = name;
            this.description = description;
            this.paramNames = paramNames;
        }
    }

    private void startMcpServer(String line) {
        if (mcpServer != null) {
            int p = mcpServer.getPort();
            System.out.println("MCP server already running on port " + p);
            printMcpConfig(p, mcpServerIndex);
            return;
        }
        int port = 9239;
        String portStr = line.substring(3).trim();
        if (!portStr.isEmpty()) {
            try {
                port = Integer.parseInt(portStr);
            } catch (NumberFormatException ignored) {
            }
        }
        int maxRetries = 10;
        for (int i = 0; i < maxRetries; i++) {
            try {
                mcpServer = new McpServer(emulator, port);
                for (PendingMcpTool tool : pendingMcpTools) {
                    mcpServer.addCustomTool(tool.name, tool.description, tool.paramNames);
                }
                pendingMcpTools.clear();
                mcpServer.start();
                scannerNeedsRefresh = true;
                mcpServer.setDebugIdle(true);
                mcpServerIndex = i;
                System.out.println("MCP server started on port " + port);
                printMcpConfig(port, i);
                return;
            } catch (IOException e) {
                mcpServer = null;
                if (i < maxRetries - 1) {
                    System.out.println("Port " + port + " is in use, trying " + (port + 1) + "...");
                    port++;
                } else {
                    System.err.println("Failed to start MCP server: " + e.getMessage());
                }
            }
        }
    }

    private int mcpServerIndex;

    private void printMcpConfig(int port, int index) {
        String serverName = index == 0 ? "unidbg-mcp-server" : "unidbg-mcp-server-" + index;
        System.out.println("Add to Cursor MCP settings:");
        System.out.println("{");
        System.out.println("  \"mcpServers\": {");
        System.out.println("    \"" + serverName + "\": {");
        System.out.println("      \"url\": \"http://localhost:" + port + "/sse\"");
        System.out.println("    }");
        System.out.println("  }");
        System.out.println("}");
    }

    private void notifyBreakpointHit(long address) {
        notifyBreakpointHit(address, null);
    }

    private void notifyBreakpointHit(long address, String reason) {
        if (mcpServer == null) return;
        JSONObject data = new JSONObject(true);
        data.put("event", "breakpoint_hit");
        data.put("pc", "0x" + Long.toHexString(address));
        if (reason != null) {
            data.put("reason", reason);
        }
        RunnableTask runningTask = emulator.getThreadDispatcher().getRunningTask();
        if (runningTask instanceof Task) {
            Task task = (Task) runningTask;
            data.put("tid", task.getId());
            data.put("is_main_thread", task.isMainThread());
        }
        Module module = emulator.getMemory().findModuleByAddress(address);
        if (module != null) {
            data.put("module", module.name);
            data.put("offset", "0x" + Long.toHexString(address - module.base));
        }
        mcpServer.queueEvent(data);
        mcpServer.broadcastNotification("breakpoint_hit", data);
    }

    void notifyExecutionCompleted() {
        if (mcpServer == null) return;
        JSONObject data = new JSONObject(true);
        data.put("event", "execution_completed");
        mcpServer.queueEvent(data);
        mcpServer.broadcastNotification("execution_completed", data);
    }

    private void notifyExecutionError(Exception e) {
        if (mcpServer == null) return;
        JSONObject data = new JSONObject(true);
        data.put("event", "execution_error");
        data.put("error", e.getClass().getName() + ": " + (e.getMessage() != null ? e.getMessage() : e.toString()));
        mcpServer.queueEvent(data);
        mcpServer.broadcastNotification("execution_error", data);
    }

    public void notifyExecutionStarted(long address) {
        if (mcpServer == null) return;
        Module module = emulator.getMemory().findModuleByAddress(address);
        if (module == null) return;
        JSONObject data = new JSONObject(true);
        data.put("event", "execution_started");
        data.put("pc", "0x" + Long.toHexString(address));
        data.put("module", module.name);
        data.put("offset", "0x" + Long.toHexString(address - module.base));
        mcpServer.queueEvent(data);
        mcpServer.broadcastNotification("execution_started", data);
    }

    @Override
    public void close() {
        if (mcpServer != null) {
            mcpServer.stop();
            mcpServer = null;
        }
    }

}
