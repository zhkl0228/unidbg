package cn.banny.unidbg;

import cn.banny.unidbg.arm.context.RegisterContext;
import cn.banny.unidbg.debugger.Debugger;
import cn.banny.unidbg.debugger.DebuggerType;
import cn.banny.unidbg.linux.android.dvm.VM;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.spi.*;
import unicorn.Unicorn;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.net.URL;

/**
 * cpu emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public interface Emulator extends Closeable, Disassembler, ValuePair {

    int getPointerSize();

    boolean is64Bit();

    int getPageAlign();

    /**
     * trace memory read
     */
    Emulator traceRead();
    Emulator traceRead(long begin, long end);

    /**
     * trace memory write
     */
    Emulator traceWrite();
    Emulator traceWrite(long begin, long end);

    /**
     * trace instruction
     * note: low performance
     */
    void traceCode();
    void traceCode(long begin, long end);

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
    Unicorn eBlock(long begin, long until);

    /**
     * show all registers
     */
    void showRegs();

    /**
     * show registers
     */
    void showRegs(int... regs);

    Module loadLibrary(File libraryFile) throws IOException;
    Module loadLibrary(File libraryFile, boolean forceCallInit) throws IOException;

    Alignment align(long addr, long size);

    Memory getMemory();

    Unicorn getUnicorn();

    int getPid();

    String getProcessName();

    /**
     * note: low performance
     */
    Debugger attach();

    Debugger attach(DebuggerType type);

    /**
     * note: low performance
     */
    Debugger attach(long begin, long end);

    Debugger attach(long begin, long end, DebuggerType type);

    void setWorkDir(File dir);
    File getWorkDir();

    SvcMemory getSvcMemory();

    SyscallHandler getSyscallHandler();

    /**
     * @param apkFile 可为null
     */
    VM createDalvikVM(File apkFile);

    String getLibraryExtension();
    String getLibraryPath();
    LibraryFile createURLibraryFile(URL url, String libName);

    Dlfcn getDlfcn();

    /**
     * @param timeout  Duration to emulate the code (in microseconds). When this value is 0, we will emulate the code in infinite time, until the code is finished.
     */
    void setTimeout(long timeout);

    <T extends RegisterContext> T getContext();

}
