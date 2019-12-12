package cn.banny.unidbg.listener;

import capstone.Capstone;
import cn.banny.unidbg.Emulator;

public interface TraceCodeListener {

    void onInstruction(Emulator emulator, long address, Capstone.CsInsn insn);

}
