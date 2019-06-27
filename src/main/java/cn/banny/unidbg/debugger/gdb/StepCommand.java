package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

class StepCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        stub.singleStep();
        stub.makePacketAndSend("OK");
        return true;
    }

}
