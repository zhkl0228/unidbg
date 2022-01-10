package com.github.unidbg.arm;

import capstone.Arm_const;
import capstone.api.Instruction;
import capstone.api.arm.OpInfo;
import capstone.api.arm.Operand;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.FunctionCallListener;

class TraceFunctionCall32 extends TraceFunctionCall {

    public TraceFunctionCall32(Emulator<?> emulator, FunctionCallListener listener) {
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
                case Arm_const.ARM_OP_IMM:
                    functionAddress = operand.getValue().getImm();
                    break;
                case Arm_const.ARM_OP_REG:
                    functionAddress = context.getIntByReg(operand.getValue().getReg());
                    break;
                default:
                    throw new UnsupportedOperationException("type=" + operand.getType());
            }
            Number[] args = new Number[4];
            for (int i = 0; i < args.length; i++) {
                args[i] = context.getIntArg(i);
            }
            pushFunction(instruction.getAddress(), functionAddress, instruction.getAddress() + instruction.getSize(), args);
        }
    }

}
