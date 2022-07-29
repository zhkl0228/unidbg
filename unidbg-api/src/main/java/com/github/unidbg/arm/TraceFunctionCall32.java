package com.github.unidbg.arm;

import capstone.api.Instruction;
import capstone.api.arm.OpInfo;
import capstone.api.arm.Operand;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.FunctionCallListener;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class TraceFunctionCall32 extends TraceFunctionCall {

    public TraceFunctionCall32(Emulator<?> emulator, FunctionCallListener listener) {
        super(emulator, listener);
    }

    @Override
    protected Instruction disassemble(long address, int size) {
        Backend backend = emulator.getBackend();
        boolean thumb = ARM.isThumb(backend);
        if (thumb) {
            return disassembleThumb(address, size);
        } else {
            return disassembleArm(address, size);
        }
    }

    private static final int ARM_BL_IMM_MASK = 0xf000000;
    private static final int ARM_BL_IMM = 0xb000000; // BL, BLX (immediate)

    private static final int ARM_BL_REG_MASK = ~0xf000000f;
    private static final int ARM_BL_REG = 0x12fff30; // BLX<c> <Rm>

    private Instruction disassembleArm(long address, int size) {
        if (size != 4) {
            throw new IllegalStateException();
        }
        byte[] code = emulator.getBackend().mem_read(address, 4);
        ByteBuffer buffer = ByteBuffer.wrap(code).order(ByteOrder.LITTLE_ENDIAN);
        int value = buffer.getInt();
        if ((value & ARM_BL_IMM_MASK) == ARM_BL_IMM ||
                (value & 0xfe000000) == 0xfa000000) { // Encoding A2: BLX <label>
            Instruction[] instructions = emulator.disassemble(address, code, false, 1);
            return instructions[0];
        }
        if ((value & ARM_BL_REG_MASK) == ARM_BL_REG) {
            Instruction[] instructions = emulator.disassemble(address, code, false, 1);
            return instructions[0];
        }
        return null;
    }

    private static final int THUMB_BL_IMM_MASK = 0xf800c000;
    private static final int THUMB_BL_IMM = 0xf000c000; // BL, BLX (immediate)

    private static final short THUMB_BL_REG_MASK = ~0x78;
    private static final short THUMB_BL_REG = 0x4780; // BLX<c> <Rm>

    private Instruction disassembleThumb(long address, int size) {
        byte[] code = emulator.getBackend().mem_read(address, size);
        if (size == 4) { // thumb2
            ByteBuffer buffer = ByteBuffer.wrap(code).order(ByteOrder.LITTLE_ENDIAN);
            int t1 = buffer.getShort() & 0xffff;
            int t2 = buffer.getShort() & 0xffff;
            int value = (t1 << 16) | t2;
            if ((value & THUMB_BL_IMM_MASK) == THUMB_BL_IMM) {
                Instruction[] instructions = emulator.disassemble(address, code, true, 1);
                return instructions[0];
            }
        } else if (size == 2) {
            ByteBuffer buffer = ByteBuffer.wrap(code).order(ByteOrder.LITTLE_ENDIAN);
            short value = buffer.getShort();
            if ((value & THUMB_BL_REG_MASK) == THUMB_BL_REG) {
                Instruction[] instructions = emulator.disassemble(address, code, true, 1);
                return instructions[0];
            }
        } else {
            throw new IllegalStateException();
        }
        return null;
    }

    @Override
    protected void onInstruction(Instruction instruction) {
        String mnemonic = instruction.getMnemonic();
        RegisterContext context = emulator.getContext();
        if ("bl".equals(mnemonic) || "blx".equals(mnemonic)) {
            OpInfo operands = (OpInfo) instruction.getOperands();
            Operand operand = operands.getOperands()[0];
            final long functionAddress;
            switch (operand.getType()) {
                case capstone.Arm_const.ARM_OP_IMM:
                    functionAddress = operand.getValue().getImm();
                    break;
                case capstone.Arm_const.ARM_OP_REG:
                    functionAddress = context.getIntByReg(instruction.mapToUnicornReg(operand.getValue().getReg()));
                    break;
                default:
                    throw new UnsupportedOperationException("type=" + operand.getType());
            }
            Number[] args = new Number[4];
            for (int i = 0; i < args.length; i++) {
                args[i] = context.getIntArg(i);
            }
            pushFunction(instruction.getAddress(), functionAddress, instruction.getAddress() + instruction.getSize(), args);
        } else {
            throw new UnsupportedOperationException();
        }
    }

}
