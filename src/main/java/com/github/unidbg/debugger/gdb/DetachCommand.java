package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;

class DetachCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        stub.makePacketAndSend("OK");
        stub.detachServer();
        return true;
    }

}
