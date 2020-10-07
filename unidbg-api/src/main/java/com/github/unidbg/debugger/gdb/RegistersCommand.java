package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.backend.Backend;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class RegistersCommand implements GdbStubCommand {

    private static final Log log = LogFactory.getLog(RegistersCommand.class);

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        Backend backend = emulator.getBackend();
        if (log.isDebugEnabled()) {
            if (emulator.is32Bit()) {
                ARM.showRegs(emulator, null);
            } else {
                ARM.showRegs64(emulator, null);
            }
        }

        if (command.startsWith("g")) {
            StringBuilder sb = new StringBuilder();
            for(int i = 0; i < stub.registers.length; i++) {
                long value = backend.reg_read(stub.registers[i]).longValue();
                if (emulator.is32Bit()) {
                    String hex = String.format("%08x", Integer.reverseBytes((int) (value & 0xffffffffL)));
                    sb.append(hex);
                } else {
                    String hex = String.format("%016x", Long.reverseBytes(value));
                    sb.append(hex);
                }
            }
            stub.makePacketAndSend(sb.toString());
        } else {
            for (int i = 0; i < stub.registers.length; i++) {
                if (emulator.is32Bit()) {
                    long value = Long.parseLong(command.substring(1 + 8 * i, 9 + 8 * i), 16);
                    backend.reg_write(stub.registers[i], Integer.reverseBytes((int) (value & 0xffffffffL)));
                } else {
                    long value = Long.parseLong(command.substring(1 + 16 * i, 9 + 16 * i), 16);
                    backend.reg_write(stub.registers[i], Long.reverseBytes(value));
                }
            }
        }
        return true;
    }

}
