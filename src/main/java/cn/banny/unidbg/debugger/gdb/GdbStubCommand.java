package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;

interface GdbStubCommand {

    boolean processCommand(Emulator emulator, GdbStub stub, String command);

}
