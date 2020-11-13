package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

class MemoryCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        try {
            int divider = command.indexOf(",");
            long address = Long.parseLong(command.substring(1, divider), 16);
            Pointer pointer = UnidbgPointer.pointer(emulator, address);
            if (pointer == null) {
                stub.makePacketAndSend("E01");
                return true;
            }
            if (command.startsWith("m")) {
                int len = Integer.parseInt(command.substring(divider + 1), 16);
                final String resp = Hex.encodeHexString(pointer.getByteArray(0, len)).toUpperCase();
                stub.makePacketAndSend(resp);
                return true;
            } else {
                int dividerForValue = command.indexOf(":");
                int len = Integer.parseInt(command.substring(divider + 1, dividerForValue), 16);
                byte[] val = Hex.decodeHex(command.substring(dividerForValue + 1).toCharArray());
                pointer.write(0, val, 0, len);
                stub.makePacketAndSend("OK");
                return true;
            }
        } catch (BackendException e) {
            stub.makePacketAndSend("E01");
            return true;
        } catch (DecoderException e) {
            throw new IllegalStateException("process memory command failed: " + command, e);
        }
    }

}
