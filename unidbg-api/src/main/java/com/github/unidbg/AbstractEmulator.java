package com.github.unidbg;

import com.github.unidbg.arm.ARMSvcMemory;
import com.github.unidbg.arm.Arguments;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.DebugServer;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.debugger.DebuggerType;
import com.github.unidbg.debugger.gdb.GdbStub;
import com.github.unidbg.debugger.ida.AndroidServer;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.listener.TraceCodeListener;
import com.github.unidbg.listener.TraceReadListener;
import com.github.unidbg.listener.TraceWriteListener;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.MemoryBlockImpl;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.MemoryWriteListener;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.util.*;

/**
 * abstract emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public abstract class AbstractEmulator<T extends NewFileIO> implements Emulator<T>, MemoryWriteListener {

    private static final Log log = LogFactory.getLog(AbstractEmulator.class);

    public static final long DEFAULT_TIMEOUT = 0;

    protected final Backend backend;

    private final int pid;

    protected long timeout = DEFAULT_TIMEOUT;

    private static final ThreadLocal<Emulator<?>> EMULATOR_THREAD_LOCAL = new ThreadLocal<>();
    public static Emulator<?> getContextEmulator() {
        return EMULATOR_THREAD_LOCAL.get();
    }
    public static void setContextEmulator(Emulator<?> emulator) {
        EMULATOR_THREAD_LOCAL.set(emulator);
    }

    private final RegisterContext registerContext;

    private final FileSystem<T> fileSystem;
    protected final SvcMemory svcMemory;

    private final Family family;

    public AbstractEmulator(boolean is64Bit, String processName, long svcBase, int svcSize, File rootDir, Family family, Collection<BackendFactory> backendFactories) {
        super();
        this.family = family;

        File targetDir = new File("target");
        if (!targetDir.exists()) {
            targetDir = FileUtils.getTempDirectory();
        }
        if (rootDir == null) {
            rootDir = new File(targetDir, FileSystem.DEFAULT_ROOT_FS);
        }
        if (rootDir.isFile()) {
            throw new IllegalArgumentException("rootDir must be directory: " + rootDir);
        }
        if (!rootDir.exists() && !rootDir.mkdirs()) {
            throw new IllegalStateException("mkdirs failed: " + rootDir);
        }
        this.fileSystem = createFileSystem(rootDir);
        this.backend = BackendFactory.createBackend(this, is64Bit, backendFactories);
        this.processName = processName == null ? "unidbg" : processName;
        this.registerContext = createRegisterContext(backend);

        this.readHook = new TraceMemoryHook(true);
        this.writeHook = new TraceMemoryHook(false);
        this.codeHook = new AssemblyCodeDumper(this);

        String name = ManagementFactory.getRuntimeMXBean().getName();
        String pid = name.split("@")[0];
        this.pid = Integer.parseInt(pid);

        setContextEmulator(this);
        this.svcMemory = new ARMSvcMemory(svcBase, svcSize, this);

        this.backend.onInitialize();
    }

    @Override
    public final int getPageAlign() {
        int pageSize = backend.getPageSize();
        if (pageSize == 0) {
            pageSize = getPageAlignInternal();
        }
        return pageSize;
    }

    protected abstract int getPageAlignInternal();

    @Override
    public Family getFamily() {
        return family;
    }

    public final SvcMemory getSvcMemory() {
        return svcMemory;
    }

    @Override
    public final FileSystem<T> getFileSystem() {
        return fileSystem;
    }

    protected abstract FileSystem<T> createFileSystem(File rootDir);

    @Override
    public boolean is64Bit() {
        return getPointerSize() == 8;
    }

    @Override
    public boolean is32Bit() {
        return getPointerSize() == 4;
    }

    protected abstract RegisterContext createRegisterContext(Backend backend);

    @SuppressWarnings("unchecked")
    @Override
    public <V extends RegisterContext> V getContext() {
        return (V) registerContext;
    }

    protected  abstract Memory createMemory(UnixSyscallHandler<T> syscallHandler, String[] envs);

    protected abstract Dlfcn createDyld(SvcMemory svcMemory);

    protected abstract UnixSyscallHandler<T> createSyscallHandler(SvcMemory svcMemory);

    @Override
    public void runAsm(String... asm) {
        byte[] shellCode = assemble(Arrays.asList(asm));

        if (shellCode.length < 2) {
            throw new IllegalStateException("run asm failed");
        }

        long spBackup = getMemory().getStackPoint();
        MemoryBlock block = MemoryBlockImpl.allocExecutable(getMemory(), shellCode.length);
        UnidbgPointer pointer = block.getPointer();
        pointer.write(0, shellCode, 0, shellCode.length);
        try {
            emulate(pointer.peer, pointer.peer + shellCode.length, 0, false);
        } finally {
            block.free();
            getMemory().setStackPoint(spBackup);
        }
    }

    protected abstract byte[] assemble(Iterable<String> assembly);

    private Debugger debugger;

    @Override
    public Debugger attach() {
        return attach(DebuggerType.CONSOLE);
    }

    @Override
    public Debugger attach(DebuggerType type) {
        if (debugger != null) {
            return debugger;
        }

        switch (type) {
            case GDB_SERVER:
                debugger = new GdbStub(this);
                break;
            case ANDROID_SERVER_V7:
                debugger = new AndroidServer(this, DebugServer.IDA_PROTOCOL_VERSION_V7);
                break;
            case CONSOLE:
            default:
                debugger = createConsoleDebugger();
                break;
        }
        if (debugger == null) {
            throw new UnsupportedOperationException();
        }

        this.backend.debugger_add(debugger, 1, 0, this);
        this.timeout = 0;
        return debugger;
    }

    protected abstract Debugger createConsoleDebugger();

    @Override
    public int getPid() {
        return pid;
    }

    private boolean traceMemoryRead, traceMemoryWrite;
    private long traceMemoryReadBegin, traceMemoryReadEnd;
    private TraceReadListener traceReadListener;
    private long traceMemoryWriteBegin, traceMemoryWriteEnd;
    private TraceWriteListener traceWriteListener;
    protected boolean traceInstruction;
    private long traceInstructionBegin, traceInstructionEnd;
    private TraceCodeListener traceCodeListener;

    @Override
    public final Emulator<T> traceRead(long begin, long end) {
        traceMemoryRead = true;
        traceMemoryReadBegin = begin;
        traceMemoryReadEnd = end;
        return this;
    }

    @Override
    public Emulator<T> traceRead(long begin, long end, TraceReadListener listener) {
        this.traceReadListener = listener;
        return traceRead(begin, end);
    }

    @Override
    public final Emulator<T> traceWrite(long begin, long end) {
        traceMemoryWrite = true;
        traceSystemMemoryWrite = true;
        traceMemoryWriteBegin = begin;
        traceMemoryWriteEnd = end;
        return this;
    }

    private boolean traceSystemMemoryWrite;

    @Override
    public void onSystemWrite(long addr, byte[] data) {
        if (!traceSystemMemoryWrite) {
            return;
        }
        long max = Math.max(addr, traceMemoryWriteBegin);
        long min = Math.min(addr + data.length, traceMemoryWriteEnd);
        if (max < min) {
            byte[] buf = new byte[(int) (min - max)];
            System.arraycopy(data, (int) (max - addr), buf, 0, buf.length);
            StringWriter writer = new StringWriter();
            writer.write("### System Memory WRITE at 0x" + Long.toHexString(max));
            new Exception().printStackTrace(new PrintWriter(writer));
            Inspector.inspect(buf, writer.toString());
        }
    }

    @Override
    public Emulator<T> traceWrite(long begin, long end, TraceWriteListener listener) {
        this.traceWriteListener = listener;
        return traceWrite(begin, end);
    }

    @Override
    public final Emulator<T> traceRead() {
        return traceRead(1, 0);
    }

    @Override
    public final Emulator<T> traceWrite() {
        return traceWrite(1, 0);
    }

    @Override
    public final void traceCode() {
        traceCode(1, 0);
    }

    @Override
    public final void traceCode(long begin, long end) {
        traceInstruction = true;
        traceInstructionBegin = begin;
        traceInstructionEnd = end;
    }

    @Override
    public void traceCode(long begin, long end, TraceCodeListener listener) {
        this.traceCodeListener = listener;
        traceCode(begin, end);
    }

    private final TraceMemoryHook readHook;
    private final TraceMemoryHook writeHook;
    private final AssemblyCodeDumper codeHook;

    @Override
    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    private File traceOutFile;

    @Override
    public void redirectTrace(File outFile) {
        this.traceOutFile = outFile;
    }

    private boolean running;

    @Override
    public boolean isRunning() {
        return running;
    }

    /**
     * Emulate machine code in a specific duration of time.
     * @param begin    Address where emulation starts
     * @param until    Address where emulation stops (i.e when this address is hit)
     * @param timeout  Duration to emulate the code (in microseconds). When this value is 0, we will emulate the code in infinite time, until the code is finished.
     */
    protected final Number emulate(long begin, long until, long timeout, boolean entry) {
        if (running) {
            backend.emu_stop();
            throw new IllegalStateException("running");
        }

        final Pointer pointer = UnidbgPointer.pointer(this, begin);
        long start = 0;
        PrintStream redirect = null;
        Thread exitHook = null;
        try {
            setContextEmulator(this);

            if (traceOutFile != null) {
                try {
                    redirect = new PrintStream(new FileOutputStream(traceOutFile, true), false);
                } catch (FileNotFoundException e) {
                    log.warn("Set trace out file failed", e);
                }
            }

            if (entry) {
                if (traceMemoryRead) {
                    traceMemoryRead = false;
                    readHook.redirect = redirect;
                    readHook.traceReadListener = traceReadListener;
                    traceReadListener = null;
                    backend.hook_add_new((ReadHook) readHook, traceMemoryReadBegin, traceMemoryReadEnd, this);
                }
                if (traceMemoryWrite) {
                    traceMemoryWrite = false;
                    writeHook.redirect = redirect;
                    writeHook.traceWriteListener = traceWriteListener;
                    traceWriteListener = null;
                    backend.hook_add_new((WriteHook) writeHook, traceMemoryWriteBegin, traceMemoryWriteEnd, this);
                }
            }
            if (traceInstruction) {
                traceInstruction = false;
                codeHook.initialize(traceInstructionBegin, traceInstructionEnd, traceCodeListener);
                traceCodeListener = null;
                codeHook.redirect = redirect;
                backend.hook_add_new(codeHook, traceInstructionBegin, traceInstructionEnd, this);
            }
            if (log.isDebugEnabled()) {
                log.debug("emulate " + pointer + " started sp=" + getStackPointer());
            }
            start = System.currentTimeMillis();
            running = true;
            if (log.isDebugEnabled()) {
                exitHook = new Thread() {
                    @Override
                    public void run() {
                        Debugger debugger = attach();
                        if (!debugger.isDebugging()) {
                            debugger.debug();
                        }
                    }
                };
                Runtime.getRuntime().addShutdownHook(exitHook);
            }
            backend.emu_start(begin, until, timeout, 0);
            if (is64Bit()) {
                return backend.reg_read(Arm64Const.UC_ARM64_REG_X0);
            } else {
                Number r0 = backend.reg_read(ArmConst.UC_ARM_REG_R0);
                Number r1 = backend.reg_read(ArmConst.UC_ARM_REG_R1);
                return (r0.intValue() & 0xffffffffL) | ((r1.intValue() & 0xffffffffL) << 32);
            }
        } catch (RuntimeException e) {
            if (!entry && e instanceof BackendException && !log.isDebugEnabled()) {
                log.warn("emulate " + pointer + " failed: sp=" + getStackPointer() + ", offset=" + (System.currentTimeMillis() - start) + "ms", e);
                return -1;
            }

            boolean enterDebug = log.isDebugEnabled();
            if (enterDebug) {
                e.printStackTrace();
                attach().debug();
            } else {
                log.warn("emulate " + pointer + " exception sp=" + getStackPointer() + ", msg=" + e.getMessage() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
            }
            return -1;
        } finally {
            if (exitHook != null) {
                Runtime.getRuntime().removeShutdownHook(exitHook);
            }
            traceSystemMemoryWrite = false;
            running = false;

            if (log.isDebugEnabled()) {
                log.debug("emulate " + pointer + " finished sp=" + getStackPointer() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
            }
        }
    }

    protected abstract Pointer getStackPointer();

    private boolean closed;

    @Override
    public synchronized final void close() throws IOException {
        if (closed) {
            throw new IOException("Already closed.");
        }

        try {
            IOUtils.closeQuietly(debugger);

            closeInternal();

            backend.destroy();
        } finally {
            closed = true;
        }
    }

    protected abstract void closeInternal();

    @Override
    public Backend getBackend() {
        return backend;
    }

    private final String processName;

    @Override
    public String getProcessName() {
        return processName == null ? "unidbg" : processName;
    }

    protected final Number[] eFunc(long begin, Arguments args, long lr, boolean entry) {
        long sp = getMemory().getStackPoint();
        int alignment = is64Bit() ? 16 : 8;
        if (sp % alignment != 0) {
            log.info("SP NOT " + alignment + " byte aligned", new Exception(getStackPointer().toString()));
        }
        final List<Number> numbers = new ArrayList<>(10);
        numbers.add(emulate(begin, lr, timeout, entry));
        numbers.addAll(args.pointers);
        return numbers.toArray(new Number[0]);
    }

    private final Map<String, Object> context = new HashMap<>();

    @Override
    public void set(String key, Object value) {
        context.put(key, value);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <V> V get(String key) {
        return (V) context.get(key);
    }

    protected abstract boolean isPaddingArgument();

    protected void dumpClass(String className) {
        throw new UnsupportedOperationException("dumpClass className=" + className);
    }

    protected void searchClass(String keywords) {
        throw new UnsupportedOperationException("searchClass keywords=" + keywords);
    }

    @Override
    public final void serialize(DataOutput out) throws IOException {
        out.writeUTF(getClass().getName());
        getMemory().serialize(out);
        getSvcMemory().serialize(out);
        getSyscallHandler().serialize(out);
        getDlfcn().serialize(out);
    }

}
