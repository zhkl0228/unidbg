package cn.banny.emulator;

import capstone.Capstone;

/**
 * disassembler
 * Created by zhkl0228 on 2017/5/9.
 */

public interface Disassembler {

    boolean printAssemble(long address, int size);
    Capstone.CsInsn[] disassemble(long address, int size, long count);
    Capstone.CsInsn[] disassemble(long address, byte[] code, boolean thumb);

}
