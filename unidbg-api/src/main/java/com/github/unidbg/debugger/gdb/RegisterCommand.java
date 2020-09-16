package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;
import unicorn.ArmConst;
import unicorn.Unicorn;

class RegisterCommand implements GdbStubCommand {

    @Override
    public boolean processCommand(Emulator<?> emulator, GdbStub stub, String command) {
        Unicorn unicorn = emulator.getUnicorn();
        if (command.startsWith("p")) {
            int reg = Integer.parseInt(command.substring(1), 16);
            long val = readRegister(unicorn, stub, reg);
            if (emulator.is32Bit()) {
                stub.makePacketAndSend(String.format("%08x", Integer.reverseBytes((int) (val & 0xffffffffL))));
            } else {
                stub.makePacketAndSend(String.format("%016x", Long.reverseBytes(val)));
            }
            return true;
        } else {
            int reg = Integer.parseInt(command.substring(1, command.indexOf('=')), 16);
            long val = Long.parseLong(command.substring(command.indexOf('=') +  1), 16);
            writeRegister(emulator, unicorn, stub, reg, val);
            stub.makePacketAndSend("OK");
            return true;
        }
    }

    private long readRegister(Unicorn unicorn, GdbStub stub, int reg) {
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
            return ((Number) unicorn.reg_read(index)).longValue();
        } else {
            return 0;
        }
    }

    private void writeRegister(Emulator<?> emulator, Unicorn unicorn, GdbStub stub, int reg, long val) {
        if (reg >= 0 && reg < stub.registers.length) {
            if (emulator.is32Bit()) {
                unicorn.reg_write(stub.registers[reg], (int) (val & 0xffffffffL));
            } else {
                unicorn.reg_write(stub.registers[reg], val);
            }
        } else if (reg == 0x19) { // for arm32
            unicorn.reg_write(ArmConst.UC_ARM_REG_CPSR, Integer.reverseBytes((int) (val & 0xffffffffL)));
        }
    }

}
