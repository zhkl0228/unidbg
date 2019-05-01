package cn.banny.emulator;

import cn.banny.emulator.arm.Arguments;
import cn.banny.emulator.debugger.Debugger;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.MemoryBlock;
import cn.banny.emulator.memory.MemoryBlockImpl;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.pointer.UnicornPointer;
import cn.banny.emulator.spi.Dlfcn;
import cn.banny.emulator.unix.UnixSyscallHandler;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.*;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * abstract emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public abstract class AbstractEmulator implements Emulator {

    private static final Log log = LogFactory.getLog(AbstractEmulator.class);

    private static final long DEFAULT_TIMEOUT = TimeUnit.HOURS.toMicros(1);

    protected final Unicorn unicorn;

    private final int pid;

    protected long timeout = DEFAULT_TIMEOUT;

    public AbstractEmulator(int unicorn_arch, int unicorn_mode, String processName) {
        super();

        this.unicorn = new Unicorn(unicorn_arch, unicorn_mode);
        this.processName = processName == null ? "emulator" : processName;

        this.readHook = new TraceMemoryHook();
        this.writeHook = new TraceMemoryHook();
        this.codeHook = new AssemblyCodeDumper(this);

        String name = ManagementFactory.getRuntimeMXBean().getName();
        String pid = name.split("@")[0];
        this.pid = Integer.parseInt(pid);
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

        MemoryBlock block = MemoryBlockImpl.allocExecutable(getMemory(), shellCode.length);
        UnicornPointer pointer = block.getPointer();
        pointer.write(0, shellCode, 0, shellCode.length);
        try {
            emulate(pointer.peer, pointer.peer + shellCode.length, 0, false);
        } finally {
            block.free();
        }
    }

    protected abstract byte[] assemble(Iterable<String> assembly);

    private Debugger debugger;

    @Override
    public Debugger attach() {
        return attach(1, 0);
    }

    @Override
    public Debugger attach(long begin, long end) {
        if (debugger != null) {
            return debugger;
        }

        debugger = createDebugger();
        if (debugger == null) {
            throw new UnsupportedOperationException();
        }

        this.unicorn.hook_add(debugger, begin, end, this);
        this.timeout = 0;
        return debugger;
    }

    protected abstract Debugger createDebugger();

    @Override
    public int getPid() {
        return pid;
    }

    private boolean traceMemoryRead, traceMemoryWrite;
    private long traceMemoryReadBegin, traceMemoryReadEnd;
    private long traceMemoryWriteBegin, traceMemoryWriteEnd;
    protected boolean traceInstruction;
    private long traceInstructionBegin, traceInstructionEnd;

    @Override
    public final Emulator traceRead(long begin, long end) {
        traceMemoryRead = true;
        traceMemoryReadBegin = begin;
        traceMemoryReadEnd = end;
        return this;
    }

    @Override
    public final Emulator traceWrite(long begin, long end) {
        traceMemoryWrite = true;
        traceMemoryWriteBegin = begin;
        traceMemoryWriteEnd = end;
        return this;
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

    private final ReadHook readHook;
    private final WriteHook writeHook;
    private final AssemblyCodeDumper codeHook;

    /**
     * Emulate machine code in a specific duration of time.
     * @param begin    Address where emulation starts
     * @param until    Address where emulation stops (i.e when this address is hit)
     * @param timeout  Duration to emulate the code (in microseconds). When this value is 0, we will emulate the code in infinite time, until the code is finished.
     */
    protected final Number emulate(long begin, long until, long timeout, boolean entry) {
        try {
            if (entry) {
                if (traceMemoryRead) {
                    traceMemoryRead = false;
                    unicorn.hook_add(readHook, traceMemoryReadBegin, traceMemoryReadEnd, this);
                }
                if (traceMemoryWrite) {
                    traceMemoryWrite = false;
                    unicorn.hook_add(writeHook, traceMemoryWriteBegin, traceMemoryWriteEnd, this);
                }
            }
            if (traceInstruction) {
                traceInstruction = false;
                codeHook.initialize(traceInstructionBegin, traceInstructionEnd);
                unicorn.hook_add(codeHook, traceInstructionBegin, traceInstructionEnd, this);
            }
            unicorn.emu_start(begin, until, timeout, (long) 0);
            return (Number) unicorn.reg_read(getPointerSize() == 4 ? ArmConst.UC_ARM_REG_R0 : Arm64Const.UC_ARM64_REG_X0);
        } catch (RuntimeException e) {
            if (!entry && e instanceof UnicornException) {
                log.warn("emulate failed", e);
                return -1;
            }

            if (log.isDebugEnabled()) {
                e.printStackTrace();
                attach().debug(this);
                IOUtils.closeQuietly(this);
                throw e;
            } else {
                log.warn("emulate exception: " + e.getMessage());
                return -1;
            }
        } finally {
            if (entry) {
                unicorn.hook_del(readHook);
                unicorn.hook_del(writeHook);
            }
            unicorn.hook_del(codeHook);
            log.debug("emulate finish");
        }
    }

    private boolean closed;

    @Override
    public synchronized final void close() throws IOException {
        if (closed) {
            throw new IOException("Already closed.");
        }

        try {
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
        return processName == null ? "emulator" : processName;
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
