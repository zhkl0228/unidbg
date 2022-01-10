package com.github.unidbg.arm;

import capstone.Arm64_const;
import capstone.api.Instruction;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.FunctionCallListener;

class TraceFunctionCall64 extends TraceFunctionCall {

    public TraceFunctionCall64(Emulator<?> emulator, FunctionCallListener listener) {
        super(emulator, listener);
    }

    @Override
    protected void onInstruction(Instruction instruction) {
        String mnemonic = instruction.getMnemonic();
        RegisterContext context = emulator.getContext();
        if (mnemonic.startsWith("bl")) {
            OpInfo operands = (OpInfo) instruction.getOperands();
            Operand operand = operands.getOperands()[0];
            final long functionAddress;
            switch (operand.getType()) {
                case Arm64_const.ARM64_OP_IMM:
                    functionAddress = operand.getValue().getImm();
                    break;
                case Arm64_const.ARM64_OP_REG:
                    functionAddress = context.getLongByReg(operand.getValue().getUnicornReg());
                    break;
                default:
                    throw new UnsupportedOperationException("type=" + operand.getType());
            }
            Number[] args = new Number[8];
            for (int i = 0; i < args.length; i++) {
                args[i] = context.getLongArg(i);
            }
            pushFunction(instruction.getAddress(), functionAddress, instruction.getAddress() + instruction.getSize(), args);
        }
    }

}
