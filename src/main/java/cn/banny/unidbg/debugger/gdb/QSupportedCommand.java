package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

class QSupportedCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        stub.makePacketAndSend("PacketSize=1024;vContSupported+;multiprocess-;xmlRegisters=arm");
        return true;
    }

}
