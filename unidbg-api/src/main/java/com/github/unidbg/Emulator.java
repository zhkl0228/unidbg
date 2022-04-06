package com.github.unidbg;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.debugger.DebuggerType;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.listener.TraceCodeListener;
import com.github.unidbg.listener.TraceReadListener;
import com.github.unidbg.listener.TraceSystemMemoryWriteListener;
import com.github.unidbg.listener.TraceWriteListener;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.serialize.Serializable;
import com.github.unidbg.spi.ArmDisassembler;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.thread.ThreadDispatcher;
import com.github.unidbg.unwind.Unwinder;

import java.io.Closeable;
import java.io.File;
import java.net.URL;

/**
 * cpu emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public interface Emulator<T extends NewFileIO> extends Closeable, ArmDisassembler, Serializable {

    int getPointerSize();

    boolean is64Bit();
    boolean is32Bit();

    int getPageAlign();

    /**
     * trace memory read
     */
    TraceHook traceRead();
    TraceHook traceRead(long begin, long end);
    TraceHook traceRead(long begin, long end, TraceReadListener listener);

    /**
     * trace memory write
     */
    TraceHook traceWrite();
    TraceHook traceWrite(long begin, long end);
    TraceHook traceWrite(long begin, long end, TraceWriteListener listener);

    void setTraceSystemMemoryWrite(long begin, long end, TraceSystemMemoryWriteListener listener);

    /**
     * trace instruction
     * note: low performance
     */
    TraceHook traceCode();
    TraceHook traceCode(long begin, long end);
    TraceHook traceCode(long begin, long end, TraceCodeListener listener);

    Number eFunc(long begin, Number... arguments);

    Number eEntry(long begin, long sp);

    /**
     * emulate signal handler
     * @param sig signal number
     * @return <code>true</code> means called handler function.
     */
    boolean emulateSignal(int sig);

    /**
     * 是否正在运行
     */
    boolean isRunning();

    /**
     * show all registers
     */
    void showRegs();

    /**
     * show registers
     */
    void showRegs(int... regs);

    Module loadLibrary(File libraryFile);
    Module loadLibrary(File libraryFile, boolean forceCallInit);

    Memory getMemory();

    Backend getBackend();

    int getPid();

    String getProcessName();

    Debugger attach();

    Debugger attach(DebuggerType type);

    FileSystem<T> getFileSystem();

    SvcMemory getSvcMemory();

    SyscallHandler<T> getSyscallHandler();

    Family getFamily();
    LibraryFile createURLibraryFile(URL url, String libName);

    Dlfcn getDlfcn();

    /**
     * @param timeout  Duration to emulate the code (in microseconds). When this value is 0, we will emulate the code in infinite time, until the code is finished.
     */
    void setTimeout(long timeout);

    <V extends RegisterContext> V getContext();

    Unwinder getUnwinder();

    void pushContext(int off);
    int popContext();

    ThreadDispatcher getThreadDispatcher();

    long getReturnAddress();

    void set(String key, Object value);
    <V> V get(String key);

}
