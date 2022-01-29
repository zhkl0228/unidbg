package com.github.unidbg.debugger;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.FunctionCall;

public abstract class FunctionCallListener {

    public abstract void onCall(Emulator<?> emulator, long callerAddress, long functionAddress);

    public abstract void postCall(Emulator<?> emulator, long callerAddress, long functionAddress, Number[] args);

    public void onDebugPushFunction(Emulator<?> emulator, FunctionCall call) {
    }
    public void onDebugPopFunction(Emulator<?> emulator, long address, FunctionCall call) {
    }

}
