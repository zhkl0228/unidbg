package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import unicorn.ArmConst;

class RegisterCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        Backend backend = emulator.getBackend();
        int reg;
        if (command.startsWith("p")) {
            reg = Integer.parseInt(command.substring(1), 16);
            long val = readRegister(backend, stub, reg);
            if (emulator.is32Bit()) {
                stub.makePacketAndSend(String.format("%08x", Integer.reverseBytes((int) (val & 0xffffffffL))));
            } else {
                stub.makePacketAndSend(String.format("%016x", Long.reverseBytes(val)));
            }
        } else {
            reg = Integer.parseInt(command.substring(1, command.indexOf('=')), 16);
            long val = Long.parseLong(command.substring(command.indexOf('=') +  1), 16);
            writeRegister(emulator, stub, reg, val);
            stub.makePacketAndSend("OK");
        }
        return true;
    }

    private long readRegister(Backend backend, GdbStub stub, int reg) {
        final int index;
        if (reg >= 0 && reg < stub.registers.length) {
            index = stub.registers[reg];
        } else if(reg == 0x18) { // for arm32
            index = ArmConst.UC_ARM_REG_FP;
        } else if(reg == 0x19) { // for arm32
            index = ArmConst.UC_ARM_REG_CPSR;
        } else {
            index = -1;
        }

        if (index != -1) {
            return backend.reg_read(index).longValue();
        } else {
            return 0;
        }
    }

    private void writeRegister(Emulator<?> emulator, GdbStub stub, int reg, long val) {
        Backend backend = emulator.getBackend();
        if (reg >= 0 && reg < stub.registers.length) {
            if (emulator.is32Bit()) {
                backend.reg_write(stub.registers[reg], (int) (val & 0xffffffffL));
            } else {
                backend.reg_write(stub.registers[reg], val);
            }
        } else if (reg == 0x19) { // for arm32
            backend.reg_write(ArmConst.UC_ARM_REG_CPSR, Integer.reverseBytes((int) (val & 0xffffffffL)));
        }
    }

}
