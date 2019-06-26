package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

public class QueryCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        if (command.startsWith("qAttached")) {
            stub.makePacketAndSend("1");
            return true;
        }
        if (command.startsWith("qfThreadInfo")) {
            stub.makePacketAndSend("m01");
            return true;
        }
        if (command.startsWith("qsThreadInfo")) {
            stub.makePacketAndSend("l");
            return true;
        }
        if (command.startsWith("qC")) {
            stub.makePacketAndSend("QC01");
            return true;
        }
        return false;
    }

}
