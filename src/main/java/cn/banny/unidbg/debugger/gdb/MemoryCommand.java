package cn.banny.unidbg.debugger.gdb;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.utils.Hex;
import com.sun.jna.Pointer;
import unicorn.UnicornException;

class MemoryCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator emulator, GdbStub stub, String command) {
        try {
            int divider = command.indexOf(",");
            long address = Long.parseLong(command.substring(1, divider), 16);
            Pointer pointer = UnicornPointer.pointer(emulator, address);
            if (pointer == null) {
                stub.makePacketAndSend("E01");
                return true;
            }
            if (command.startsWith("m")) {
                int len = Integer.parseInt(command.substring(divider + 1));
                final String resp = Hex.encodeHexString(pointer.getByteArray(0, len)).toUpperCase();
                stub.makePacketAndSend(resp);
                return true;
            } else {
                int dividerForValue = command.indexOf(":");
                int len = Integer.parseInt(command.substring(divider + 1, dividerForValue));
                byte[] val = Hex.decodeHex(command.substring(dividerForValue + 1).toCharArray());
                pointer.write(0, val, 0, len);
                stub.makePacketAndSend("OK");
                return true;
            }
        } catch (UnicornException e) {
            stub.makePacketAndSend("E00");
            return true;
        } catch (Hex.DecoderException e) {
            throw new IllegalStateException("process memory command failed: " + command, e);
        }
    }

}
