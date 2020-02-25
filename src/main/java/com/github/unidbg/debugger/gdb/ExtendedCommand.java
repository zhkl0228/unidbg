package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;

class ExtendedCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        if ("vCont?".equals(command)) {
            stub.makePacketAndSend("vCont;c;s");
            return true;
        }
        if ("vCont;c".equals(command)) {
            stub.resumeRun();
            return true;
        }
        if ("vCont;s".equals(command)) {
            stub.singleStep();
            return true;
        }
        return false;
    }

}
