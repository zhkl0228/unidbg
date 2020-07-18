package com.github.unidbg.listener;

import capstone.Capstone;
import com.github.unidbg.Emulator;

public interface TraceCodeListener {

    void onInstruction(Emulator<?> emulator, long address, Capstone.CsInsn insn);

}
