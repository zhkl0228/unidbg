package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

class QSupportedCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        stub.makePacketAndSend("PacketSize=1024;swbreak+;vContSupported-;multiprocess-;" + (emulator.getPointerSize() == 4 ? "xmlRegisters=arm" : "xmlRegisters=arm64"));
        return true;
    }

}
