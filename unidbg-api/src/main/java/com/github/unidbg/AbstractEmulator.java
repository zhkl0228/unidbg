package com.github.unidbg;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.arm.ARMSvcMemory;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.WriteHook;
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
import com.github.unidbg.listener.TraceSystemMemoryWriteListener;
import com.github.unidbg.listener.TraceWriteListener;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.MemoryWriteListener;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.thread.MainTask;
import com.github.unidbg.thread.PopContextException;
import com.github.unidbg.thread.ThreadContextSwitchException;
import com.github.unidbg.thread.ThreadDispatcher;
import com.github.unidbg.thread.UniThreadDispatcher;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.io.DataOutput;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.management.ManagementFactory;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Stack;

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

    private final RegisterContext registerContext;

    private final FileSystem<T> fileSystem;
    protected final SvcMemory svcMemory;

    private final Family family;

    protected final DateFormat dateFormat = new SimpleDateFormat("[HH:mm:ss SSS]");

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

        String name = ManagementFactory.getRuntimeMXBean().getName();
        String pid = name.split("@")[0];
        this.pid = Integer.parseInt(pid) & 0x7fff;

        this.svcMemory = new ARMSvcMemory(svcBase, svcSize, this);
        this.threadDispatcher = createThreadDispatcher();

        this.backend.onInitialize();
    }

    protected ThreadDispatcher createThreadDispatcher() {
        return new UniThreadDispatcher(this);
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

    @Override
    public final TraceHook traceRead(long begin, long end) {
        return traceRead(begin, end, null);
    }

    @Override
    public TraceHook traceRead(long begin, long end, TraceReadListener listener) {
        TraceMemoryHook hook = new TraceMemoryHook(true);
        if (listener != null) {
            hook.traceReadListener = listener;
        }
        backend.hook_add_new((ReadHook) hook, begin, end, this);
        return hook;
    }

    @Override
    public final TraceHook traceWrite(long begin, long end) {
        return traceWrite(begin, end, null);
    }

    private long traceSystemMemoryWriteBegin;
    private long traceSystemMemoryWriteEnd;
    private boolean traceSystemMemoryWrite;
    private TraceSystemMemoryWriteListener traceSystemMemoryWriteListener;

    @Override
    public void setTraceSystemMemoryWrite(long begin, long end, TraceSystemMemoryWriteListener listener) {
        traceSystemMemoryWrite = true;
        traceSystemMemoryWriteBegin = begin;
        traceSystemMemoryWriteEnd = end;
        traceSystemMemoryWriteListener = listener;
    }

    @Override
    public void onSystemWrite(long addr, byte[] data) {
        if (!traceSystemMemoryWrite) {
            return;
        }
        long max = Math.max(addr, traceSystemMemoryWriteBegin);
        long min = Math.min(addr + data.length, traceSystemMemoryWriteEnd);
        if (max < min) {
            byte[] buf = new byte[(int) (min - max)];
            System.arraycopy(data, (int) (max - addr), buf, 0, buf.length);
            if (traceSystemMemoryWriteListener != null) {
                traceSystemMemoryWriteListener.onWrite(this, addr, buf);
            } else {
                StringWriter writer = new StringWriter();
                writer.write("### System Memory WRITE at 0x" + Long.toHexString(max) + "\n");
                new Exception().printStackTrace(new PrintWriter(writer));
                Inspector.inspect(buf, writer.toString());
            }
        }
    }

    @Override
    public TraceHook traceWrite(long begin, long end, TraceWriteListener listener) {
        TraceMemoryHook hook = new TraceMemoryHook(false);
        if (listener != null) {
            hook.traceWriteListener = listener;
        }
        backend.hook_add_new((WriteHook) hook, begin, end, this);
        return hook;
    }

    @Override
    public final TraceHook traceRead() {
        return traceRead(1, 0);
    }

    @Override
    public final TraceHook traceWrite() {
        return traceWrite(1, 0);
    }

    @Override
    public final TraceHook traceCode() {
        return traceCode(1, 0);
    }

    @Override
    public final TraceHook traceCode(long begin, long end) {
        return traceCode(begin, end, null);
    }

    @Override
    public TraceHook traceCode(long begin, long end, TraceCodeListener listener) {
        AssemblyCodeDumper hook = new AssemblyCodeDumper(this, begin, end, listener);
        backend.hook_add_new(hook, begin, end, this);
        return hook;
    }

    @Override
    public void setTimeout(long timeout) {
        this.timeout = timeout;
    }

    private boolean running;

    @Override
    public boolean isRunning() {
        return running;
    }

    private final ThreadDispatcher threadDispatcher;

    @Override
    public ThreadDispatcher getThreadDispatcher() {
        return threadDispatcher;
    }

    @Override
    public boolean emulateSignal(int sig) {
        MainTask main = getSyscallHandler().createSignalHandlerTask(this, sig);
        if (main == null) {
            return false;
        } else {
            Memory memory = getMemory();
            long spBackup = memory.getStackPoint();
            try {
                threadDispatcher.runMainForResult(main);
            } finally {
                memory.setStackPoint(spBackup);
            }
            return true;
        }
    }

    protected final Number runMainForResult(MainTask task) {
        Memory memory = getMemory();
        long spBackup = memory.getStackPoint();
        try {
            return getThreadDispatcher().runMainForResult(task);
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    /**
     * @return <code>null</code>表示执行未完成，需要线程调度
     */
    public final Number emulate(long begin, long until) throws PopContextException {
        if (running) {
            backend.emu_stop();
            throw new IllegalStateException("running");
        }
        if (is32Bit()) {
            begin &= 0xffffffffL;
        }

        final Pointer pointer = UnidbgPointer.pointer(this, begin);
        long start = 0;
        Thread exitHook = null;
        try {
            if (log.isDebugEnabled()) {
                log.debug("emulate " + pointer + " started sp=" + getStackPointer());
            }
            start = System.currentTimeMillis();
            running = true;
            if (log.isDebugEnabled()) {
                exitHook = new Thread() {
                    @Override
                    public void run() {
                        backend.emu_stop();
                        Debugger debugger = attach();
                        if (!debugger.isDebugging()) {
                            debugger.debug();
                        }
                    }
                };
                Runtime.getRuntime().addShutdownHook(exitHook);
            }
            backend.emu_start(begin, until, 0, 0);
            if (is64Bit()) {
                return backend.reg_read(Arm64Const.UC_ARM64_REG_X0);
            } else {
                Number r0 = backend.reg_read(ArmConst.UC_ARM_REG_R0);
                Number r1 = backend.reg_read(ArmConst.UC_ARM_REG_R1);
                return (r0.intValue() & 0xffffffffL) | ((r1.intValue() & 0xffffffffL) << 32);
            }
        } catch (ThreadContextSwitchException e) {
            e.syncReturnValue(this);
            if (log.isTraceEnabled()) {
                e.printStackTrace();
            }
            return null;
        } catch (PopContextException e) {
            throw e;
        } catch (RuntimeException e) {
            return handleEmuException(e, pointer, start);
        } finally {
            if (exitHook != null) {
                Runtime.getRuntime().removeShutdownHook(exitHook);
            }
            running = false;

            if (log.isDebugEnabled()) {
                log.debug("emulate " + pointer + " finished sp=" + getStackPointer() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
            }
        }
    }

    private int handleEmuException(RuntimeException e, Pointer pointer, long start) {
        boolean enterDebug = log.isDebugEnabled();
        if (enterDebug || !log.isWarnEnabled()) {
            e.printStackTrace();
            attach().debug();
        } else {
            String msg = e.getMessage();
            if (msg == null) {
                msg = e.getClass().getName();
            }
            log.warn("emulate " + pointer + " exception sp=" + getStackPointer() + ", msg=" + msg + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        return -1;
    }

    public abstract Pointer getStackPointer();

    private boolean closed;

    @Override
    public synchronized final void close() throws IOException {
        if (closed) {
            throw new IOException("Already closed.");
        }

        try {
            IOUtils.close(debugger);

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

    protected void dumpGPBProtobufMsg(String className) {
        throw new UnsupportedOperationException("dumpGPBProtobufMsg className=" + className);
    }

    @Override
    public final void serialize(DataOutput out) throws IOException {
        out.writeUTF(getClass().getName());
        getMemory().serialize(out);
        getSvcMemory().serialize(out);
        getSyscallHandler().serialize(out);
        getDlfcn().serialize(out);
    }

    private static class Context {
        private final long ctx;
        private final int off;
        Context(long ctx, int off) {
            this.ctx = ctx;
            this.off = off;
        }
        void restoreAndFree(Backend backend) {
            backend.context_restore(ctx);
            backend.context_free(ctx);
        }
    }

    private final Stack<Context> contextStack = new Stack<>();

    @Override
    public void pushContext(int off) {
        long context = backend.context_alloc();
        backend.context_save(context);
        contextStack.push(new Context(context, off));
    }

    @Override
    public int popContext() {
        Context ctx = contextStack.pop();
        ctx.restoreAndFree(backend);
        return ctx.off;
    }

}
