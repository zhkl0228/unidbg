package com.github.unidbg.arm.backend.hypervisor.arm64;

import capstone.api.Disassembler;

public interface MemorySizeDetector {

    int detectReadSize(Disassembler disassembler, byte[] code, long pc);

}
