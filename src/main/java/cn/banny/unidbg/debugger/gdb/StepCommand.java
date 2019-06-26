package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

class StepCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        /*stub.system.step(1);
        stub.makePacketAndSend("S" + GdbStub.SIGTRAP);*/
        return false;
    }

}
