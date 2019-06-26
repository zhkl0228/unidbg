package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

class BreakpointCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        int divider = command.substring(3).indexOf(",");
        long address = Long.parseLong(command.substring(3, divider + 3), 16);

        if (command.startsWith("Z0")) {
            stub.addBreakPoint(address);
        } else {
            stub.removeBreakPoint(address);
        }
        stub.makePacketAndSend("OK");
        return true;
    }

}
