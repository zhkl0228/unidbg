package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

class KillCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        stub.send("+");
        stub.shutdownServer();
        System.exit(9);
        return true;
    }

}
