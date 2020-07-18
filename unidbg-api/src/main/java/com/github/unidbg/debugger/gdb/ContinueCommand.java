package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;

class ContinueCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        stub.resumeRun();
        stub.send("+");
        return true;
    }

}
