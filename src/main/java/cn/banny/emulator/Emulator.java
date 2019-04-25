package cn.banny.emulator;

import cn.banny.emulator.debugger.Debugger;
import cn.banny.emulator.linux.android.dvm.VM;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.spi.Disassembler;
import cn.banny.emulator.spi.LibraryFile;
import cn.banny.emulator.spi.SyscallHandler;
import cn.banny.emulator.spi.ValuePair;
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

    /**
     * note: low performance
     */
    Debugger attach(long begin, long end);

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

}
