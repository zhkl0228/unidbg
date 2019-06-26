package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

public class QueryCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        if (command.startsWith("qAttached")) {
            stub.makePacketAndSend("1");
            return true;
        }
        return false;
    }

}
