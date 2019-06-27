package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

class ContinueCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        stub.resumeRun();
        stub.send("+");
        return true;
    }

}
