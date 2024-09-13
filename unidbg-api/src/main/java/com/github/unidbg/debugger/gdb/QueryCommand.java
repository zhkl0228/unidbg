package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;
import com.github.unidbg.debugger.DebugServer;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

class QueryCommand implements GdbStubCommand {

    private static final Logger log = LoggerFactory.getLogger(QueryCommand.class);

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        if (command.startsWith("qSupported")) {
            stub.makePacketAndSend("PacketSize=" + DebugServer.PACKET_SIZE + ";vContSupported+;multiprocess-;xmlRegisters=arm");
            return true;
        }
        if (command.startsWith("qAttached")) {
            stub.makePacketAndSend("1");
            return true;
        }
        if (command.startsWith("qC")) {
            stub.makePacketAndSend("QC1");
            return true;
        }
        if (command.startsWith("qfThreadInfo")) {
            stub.makePacketAndSend("m01");
            return true;
        }
        if (command.startsWith("qsThreadInfo")) {
            stub.makePacketAndSend("l");
            return true;
        }
        if (command.startsWith("qRcmd,")) {
            try {
                String cmd = new String(Hex.decodeHex(command.substring(6).toCharArray()), StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("qRcmd={}", cmd);
                }
                stub.makePacketAndSend("E01");
                return true;
            } catch (DecoderException e) {
                throw new IllegalStateException(e);
            }
        }
        return false;
    }

}
