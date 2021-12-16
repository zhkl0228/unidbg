package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;

public abstract class BaseTask implements Disposable {

    @Override
    public void destroy(AbstractEmulator<?> emulator) {
        if (stackBlock != null) {
            stackBlock.free();
            stackBlock = null;
        }
    }

    public static final int THREAD_STACK_SIZE = 0x80000;

    private MemoryBlock stackBlock;

    protected final UnidbgPointer allocateStack(Emulator<?> emulator) {
        if (stackBlock == null) {
            stackBlock = emulator.getMemory().malloc(THREAD_STACK_SIZE, true);
        }
        return stackBlock.getPointer().share(THREAD_STACK_SIZE, 0);
    }

}
