package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;

interface GdbStubCommand {

    boolean processCommand(Emulator<?> emulator, GdbStub stub, String command);

}
