package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;

class BreakpointCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        int divider = command.substring(3).indexOf(",");
        long address = Long.parseLong(command.substring(3, divider + 3), 16);

        /*
         * 2: 16-bit Thumb mode breakpoint.
         * 3: 32-bit Thumb mode (Thumb-2) breakpoint.
         * 4: 32-bit ARM mode breakpoint.
         */
        int type = Integer.parseInt(command.substring(divider + 4));
        boolean isThumb = type == 2 || type == 3;
        if (isThumb) {
            address |= 1;
        }

        if (command.startsWith("Z0")) {
            stub.addBreakPoint(address);
        } else {
            stub.removeBreakPoint(address);
        }
        stub.makePacketAndSend("OK");
        return true;
    }

}
