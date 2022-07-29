package com.github.unidbg.arm;

import capstone.api.Instruction;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.FunctionCallListener;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class TraceFunctionCall64 extends TraceFunctionCall {

    public TraceFunctionCall64(Emulator<?> emulator, FunctionCallListener listener) {
        super(emulator, listener);
    }

    private static final int BL_MASK = ~0x3ffffff;
    private static final int BL = 0x94000000; // BL <label>

    private static final int BLR_MASK = ~0x3e0;
    private static final int BLR = 0xd63f0000; // BLR <Xn>

    @Override
    protected Instruction disassemble(long address, int size) {
        if (size != 4) {
            throw new IllegalStateException();
        }
        byte[] code = emulator.getBackend().mem_read(address, 4);
        ByteBuffer buffer = ByteBuffer.wrap(code).order(ByteOrder.LITTLE_ENDIAN);
        int value = buffer.getInt();
        if ((value & BL_MASK) == BL) {
            Instruction[] instructions = emulator.disassemble(address, code, false, 1);
            return instructions[0];
        }
        if ((value & BLR_MASK) == BLR) {
            Instruction[] instructions = emulator.disassemble(address, code, false, 1);
            return instructions[0];
        }
        return null;
    }

    @Override
    protected void onInstruction(Instruction instruction) {
        String mnemonic = instruction.getMnemonic();
        RegisterContext context = emulator.getContext();
        if ("bl".equals(mnemonic) || "blr".equals(mnemonic)) {
            OpInfo operands = (OpInfo) instruction.getOperands();
            Operand operand = operands.getOperands()[0];
            final long functionAddress;
            switch (operand.getType()) {
                case capstone.Arm64_const.ARM64_OP_IMM:
                    functionAddress = operand.getValue().getImm();
                    break;
                case capstone.Arm64_const.ARM64_OP_REG:
                    functionAddress = context.getLongByReg(instruction.mapToUnicornReg(operand.getValue().getReg()));
                    break;
                default:
                    throw new UnsupportedOperationException("type=" + operand.getType());
            }
            Number[] args = new Number[8];
            for (int i = 0; i < args.length; i++) {
                args[i] = context.getLongArg(i);
            }
            pushFunction(instruction.getAddress(), functionAddress, instruction.getAddress() + instruction.getSize(), args);
        } else {
            throw new UnsupportedOperationException();
        }
    }

}
