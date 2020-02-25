package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;

class KillCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        stub.send("+");
        stub.shutdownServer();
        System.exit(9);
        return true;
    }

}
