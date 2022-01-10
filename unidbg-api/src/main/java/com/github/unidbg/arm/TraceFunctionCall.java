package com.github.unidbg.arm;

import capstone.api.Instruction;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.debugger.FunctionCallListener;
import org.apache.commons.collections4.Bag;
import org.apache.commons.collections4.bag.HashBag;

import java.util.Stack;

abstract class TraceFunctionCall implements CodeHook {

    protected final Emulator<?> emulator;
    private final FunctionCallListener listener;

    TraceFunctionCall(Emulator<?> emulator, FunctionCallListener listener) {
        this.emulator = emulator;
        this.listener = listener;
    }

    private static class FunctionCall {
        private final long callerAddress;
        private final long functionAddress;
        private final long returnAddress;
        private final Number[] args;
        public FunctionCall(long callerAddress, long functionAddress, long returnAddress, Number[] args) {
            this.callerAddress = callerAddress;
            this.functionAddress = functionAddress;
            this.returnAddress = returnAddress;
            this.args = args;
        }
    }

    private final Stack<FunctionCall> stack = new Stack<>();
    private final Bag<Long> bag = new HashBag<>();

    final void pushFunction(long callerAddress, long functionAddress, long returnAddress, Number[] args) {
        stack.push(new FunctionCall(callerAddress, functionAddress, returnAddress, args));
        bag.add(returnAddress);
        listener.onCall(emulator, callerAddress, functionAddress);
    }

    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        if (bag.remove(address)) {
            FunctionCall functionCall = stack.pop();
            if (functionCall.returnAddress != address) {
                throw new IllegalStateException();
            } else {
                listener.postCall(emulator, functionCall.callerAddress, functionCall.functionAddress, functionCall.args);
            }
        }
        try {
            Instruction instruction = emulator.disassemble(address, size, 1)[0];
            onInstruction(instruction);
        } catch (BackendException e) {
            throw new IllegalStateException(e);
        }
    }

    protected abstract void onInstruction(Instruction instruction);

    private UnHook unHook;

    @Override
    public void onAttach(UnHook unHook) {
        this.unHook = unHook;
    }

    @Override
    public void detach() {
        if (unHook != null) {
            unHook.unhook();
            unHook = null;
        }
    }

}
