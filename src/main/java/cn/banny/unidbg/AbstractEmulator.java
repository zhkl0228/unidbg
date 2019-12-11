package cn.banny.unidbg;

import cn.banny.unidbg.arm.Arguments;
import cn.banny.unidbg.arm.context.RegisterContext;
import cn.banny.unidbg.debugger.DebugServer;
import cn.banny.unidbg.debugger.Debugger;
import cn.banny.unidbg.debugger.DebuggerType;
import cn.banny.unidbg.debugger.gdb.GdbStub;
import cn.banny.unidbg.debugger.ida.AndroidServer;
import cn.banny.unidbg.listener.TraceCodeListener;
import cn.banny.unidbg.listener.TraceReadListener;
import cn.banny.unidbg.listener.TraceWriteListener;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.memory.MemoryBlock;
import cn.banny.unidbg.memory.MemoryBlockImpl;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.unidbg.spi.Dlfcn;
import cn.banny.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * abstract emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public abstract class AbstractEmulator implements Emulator {

    private static final Log log = LogFactory.getLog(AbstractEmulator.class);

    public static final long DEFAULT_TIMEOUT = TimeUnit.HOURS.toMicros(1);

    protected final Unicorn unicorn;

    private final int pid;

    protected long timeout = DEFAULT_TIMEOUT;

    public static final ThreadLocal<Integer> POINTER_SIZE = new ThreadLocal<>();
    static {
        POINTER_SIZE.set(Native.POINTER_SIZE);
    }

    private final RegisterContext registerContext;

    public AbstractEmulator(int unicorn_arch, int unicorn_mode, String processName) {
        super();

        this.unicorn = new Unicorn(unicorn_arch, unicorn_mode);
        this.processName = processName == null ? "unidbg" : processName;
        this.registerContext = createRegisterContext(unicorn);

        this.readHook = new TraceMemoryHook(true);
        this.writeHook = new TraceMemoryHook(false);
        this.codeHook = new AssemblyCodeDumper(this);

        String name = ManagementFactory.getRuntimeMXBean().getName();
        String pid = name.split("@")[0];
        this.pid = Integer.parseInt(pid);

        POINTER_SIZE.set(getPointerSize());
    }

    @Override
    public boolean is64Bit() {
        return getPointerSize() == 8;
    }

    protected abstract RegisterContext createRegisterContext(Unicorn unicorn);

    @SuppressWarnings("unchecked")
    @Override
    public <T extends RegisterContext> T getContext() {
        return (T) registerContext;
    }

    protected  abstract Memory createMemory(UnixSyscallHandler syscallHandler);

    protected abstract Dlfcn createDyld(SvcMemory svcMemory);

    protected abstract UnixSyscallHandler createSyscallHandler(SvcMemory svcMemory);

    @Override
    public void runAsm(String... asm) {
        byte[] shellCode = assemble(Arrays.asList(asm));

        if (shellCode.length < 2) {
            throw new IllegalStateException("run asm failed");
        }

        long spBackup = getMemory().getStackPoint();
        MemoryBlock block = MemoryBlockImpl.allocExecutable(getMemory(), shellCode.length);
        UnicornPointer pointer = block.getPointer();
        pointer.write(0, shellCode, 0, shellCode.length);
        try {
            emulate(pointer.peer, pointer.peer + shellCode.length, 0, false);
        } finally {
            block.free(false);
            getMemory().setStackPoint(spBackup);
        }
    }

    protected abstract byte[] assemble(Iterable<String> assembly);

    private Debugger debugger;

    @Override
    public Debugger attach() {
        return attach(DebuggerType.SIMPLE);
    }

    @Override
    public Debugger attach(DebuggerType type) {
        return attach(1, 0, type);
    }

    @Override
    public Debugger attach(long begin, long end, DebuggerType type) {
        if (debugger != null) {
            return debugger;
        }

        switch (type) {
            case GDB_SERVER:
                debugger = new GdbStub(this);
                break;
            case ANDROID_SERVER_V73:
                debugger = new AndroidServer(this, DebugServer.IDA_PROTOCOL_VERSION_73);
                break;
            case SIMPLE:
            default:
                debugger = createDebugger();
                break;
        }
        if (debugger == null) {
            throw new UnsupportedOperationException();
        }

        if (!debugger.isSoftBreakpoint()) {
            this.unicorn.hook_add(debugger, begin, end, this);
        }
        this.timeout = 0;
        return debugger;
    }

    @Override
    public Debugger attach(long begin, long end) {
        return attach(begin, end, DebuggerType.SIMPLE);
    }

    protected abstract Debugger createDebugger();

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
    public final Emulator traceRead(long begin, long end) {
        traceMemoryRead = true;
        traceMemoryReadBegin = begin;
        traceMemoryReadEnd = end;
        return this;
    }

    @Override
    public Emulator traceRead(long begin, long end, TraceReadListener listener) {
        this.traceReadListener = listener;
        return traceRead(begin, end);
    }

    @Override
    public final Emulator traceWrite(long begin, long end) {
        traceMemoryWrite = true;
        traceMemoryWriteBegin = begin;
        traceMemoryWriteEnd = end;
        return this;
    }

    @Override
    public Emulator traceWrite(long begin, long end, TraceWriteListener listener) {
        this.traceWriteListener = listener;
        return traceWrite(begin, end);
    }

    @Override
    public final Emulator traceRead() {
        return traceRead(1, 0);
    }

    @Override
    public final Emulator traceWrite() {
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

    /**
     * Emulate machine code in a specific duration of time.
     * @param begin    Address where emulation starts
     * @param until    Address where emulation stops (i.e when this address is hit)
     * @param timeout  Duration to emulate the code (in microseconds). When this value is 0, we will emulate the code in infinite time, until the code is finished.
     */
    protected final Number emulate(long begin, long until, long timeout, boolean entry) {
        final Pointer pointer = UnicornPointer.pointer(this, begin);
        long start = 0;
        PrintStream redirect = null;
        try {
            POINTER_SIZE.set(getPointerSize());

            if (traceOutFile != null) {
                try {
                    redirect = new PrintStream(traceOutFile);
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
                    unicorn.hook_add(readHook, traceMemoryReadBegin, traceMemoryReadEnd, this);
                }
                if (traceMemoryWrite) {
                    traceMemoryWrite = false;
                    writeHook.redirect = redirect;
                    writeHook.traceWriteListener = traceWriteListener;
                    traceWriteListener = null;
                    unicorn.hook_add(writeHook, traceMemoryWriteBegin, traceMemoryWriteEnd, this);
                }
            }
            if (traceInstruction) {
                traceInstruction = false;
                codeHook.initialize(traceInstructionBegin, traceInstructionEnd, traceCodeListener);
                traceCodeListener = null;
                codeHook.redirect = redirect;
                unicorn.hook_add(codeHook, traceInstructionBegin, traceInstructionEnd, this);
            }
            log.debug("emulate " + pointer + " started sp=" + getStackPointer());
            start = System.currentTimeMillis();
            unicorn.emu_start(begin, until, timeout, 0);
            return (Number) unicorn.reg_read(is64Bit() ? Arm64Const.UC_ARM64_REG_X0 : ArmConst.UC_ARM_REG_R0);
        } catch (RuntimeException e) {
            if (!entry && e instanceof UnicornException && !log.isDebugEnabled()) {
                log.warn("emulate " + pointer + " failed: sp=" + getStackPointer() + ", offset=" + (System.currentTimeMillis() - start) + "ms", e);
                return -1;
            }

            boolean enterDebug = log.isDebugEnabled();
            if (enterDebug) {
                e.printStackTrace();
                attach().debug();
                IOUtils.closeQuietly(this);
                throw e;
            } else {
                log.warn("emulate " + pointer + " exception sp=" + getStackPointer() + ", msg=" + e.getMessage() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
                return -1;
            }
        } finally {
            if (entry) {
                unicorn.hook_del(readHook);
                unicorn.hook_del(writeHook);
                readHook.redirect = null;
                writeHook.redirect = null;
            }
            unicorn.hook_del(codeHook);
            codeHook.redirect = null;
            log.debug("emulate " + pointer + " finished sp=" + getStackPointer() + ", offset=" + (System.currentTimeMillis() - start) + "ms");

            IOUtils.closeQuietly(redirect);
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

            // unicorn.close(); // May cause crash
        } finally {
            closed = true;
        }
    }

    protected abstract void closeInternal();

    @Override
    public Alignment align(long addr, long size) {
        long to = getPageAlign();
        long mask = -to;
        long right = addr + size;
        right = (right + to - 1) & mask;
        addr &= mask;
        size = right - addr;
        size = (size + to - 1) & mask;
        return new Alignment(addr, size);
    }

    @Override
    public Unicorn getUnicorn() {
        return unicorn;
    }

    private final String processName;

    @Override
    public String getProcessName() {
        return processName == null ? "unidbg" : processName;
    }

    private File workDir;

    @Override
    public void setWorkDir(File dir) {
        this.workDir = dir;
    }

    @Override
    public File getWorkDir() {
        return workDir;
    }

    protected final Number[] eFunc(long begin, Arguments args, long lr, boolean entry) {
        if (log.isDebugEnabled()) {
            long sp = getMemory().getStackPoint();
            if (sp % 8 != 0) {
                log.debug("SP NOT 8 byte aligned", new Exception(getStackPointer().toString()));
            }
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
    public <T> T get(String key) {
        return (T) context.get(key);
    }

}
