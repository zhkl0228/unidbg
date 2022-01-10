package com.github.unidbg.debugger;

import com.github.unidbg.Emulator;

public interface FunctionCallListener {

    void onCall(Emulator<?> emulator, long callerAddress, long functionAddress);

    void postCall(Emulator<?> emulator, long callerAddress, long functionAddress, Number[] args);

}
