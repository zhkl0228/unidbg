package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;

public class FunctionCall {

    public final long callerAddress;
    public final long functionAddress;
    public final long returnAddress;
    public final Number[] args;

    public FunctionCall(long callerAddress, long functionAddress, long returnAddress, Number[] args) {
        this.callerAddress = callerAddress;
        this.functionAddress = functionAddress;
        this.returnAddress = returnAddress;
        this.args = args;
    }

    public String toReadableString(Emulator<?> emulator) {
        return "FunctionCall{" +
                "callerAddress=" + UnidbgPointer.pointer(emulator, callerAddress) +
                ", functionAddress=" + UnidbgPointer.pointer(emulator, functionAddress) +
                ", returnAddress=" + UnidbgPointer.pointer(emulator, returnAddress) +
                '}';
    }

}
