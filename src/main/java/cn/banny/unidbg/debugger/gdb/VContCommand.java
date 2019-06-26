package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

public class VContCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        if ("vCont?".equals(command)) {
            stub.makePacketAndSend("vCont;s");
            return true;
        }

        return false;
    }

}
