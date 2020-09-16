package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;

class EnableExtendedModeCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        stub.makePacketAndSend("OK");
        return true;
    }

}
