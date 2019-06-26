package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

class DetachCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        stub.makePacketAndSend("OK");
        stub.resumeRun();
        stub.detachServer();
        return true;
    }

}
