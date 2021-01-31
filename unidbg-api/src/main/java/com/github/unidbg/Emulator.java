package com.github.unidbg;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.debugger.DebuggerType;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.listener.TraceCodeListener;
import com.github.unidbg.listener.TraceReadListener;
import com.github.unidbg.listener.TraceWriteListener;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.serialize.Serializable;
import com.github.unidbg.spi.*;
import com.github.unidbg.unwind.Unwinder;

import java.io.Closeable;
import java.io.File;
import java.net.URL;

/**
 * cpu emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public interface Emulator<T extends NewFileIO> extends Closeable, Disassembler, ValuePair, Serializable {

    int getPointerSize();

    boolean is64Bit();
    boolean is32Bit();

    int getPageAlign();

    /**
     * trace memory read
     */
    Emulator<T> traceRead();
    Emulator<T> traceRead(long begin, long end);
    Emulator<T> traceRead(long begin, long end, TraceReadListener listener);

    /**
     * trace memory write
     */
    Emulator<T> traceWrite();
    Emulator<T> traceWrite(long begin, long end);
    Emulator<T> traceWrite(long begin, long end, TraceWriteListener listener);

    /**
     * trace instruction
     * note: low performance
     */
    void traceCode();
    void traceCode(long begin, long end);
    void traceCode(long begin, long end, TraceCodeListener listener);

    /**
     * redirect trace out
     */
    void redirectTrace(File outFile);

    void runAsm(String...asm);

    Number[] eFunc(long begin, Number... arguments);

    void eInit(long begin, Number... arguments);

    Number eEntry(long begin, long sp);

    /**
     * emulate block
     * @param begin start address
     * @param until stop address
     */
    @Deprecated
    void eBlock(long begin, long until);

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

}
