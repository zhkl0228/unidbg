package com.github.unidbg.spi;

import capstone.api.Instruction;
import com.github.unidbg.arm.InstructionVisitor;

import java.io.PrintStream;

/**
 * disassembler
 * Created by zhkl0228 on 2017/5/9.
 */

public interface ArmDisassembler {

    Instruction[] printAssemble(PrintStream out, long address, int size, int maxLengthLibraryName, InstructionVisitor visitor);
    Instruction[] disassemble(long address, int size, long count);
    Instruction[] disassemble(long address, byte[] code, boolean thumb, long count);

}
