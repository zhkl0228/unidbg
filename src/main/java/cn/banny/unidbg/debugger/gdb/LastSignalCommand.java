package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

class LastSignalCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        stub.makePacketAndSend("S" + GdbStub.SIGTRAP);
        return true;
    }

}
