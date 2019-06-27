package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

class EnableExtendedModeCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        stub.makePacketAndSend("OK");
        return true;
    }

}
