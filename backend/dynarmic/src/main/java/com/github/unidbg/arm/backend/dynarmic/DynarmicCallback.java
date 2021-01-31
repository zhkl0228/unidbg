package com.github.unidbg.arm.backend.dynarmic;

public interface DynarmicCallback {

    void callSVC(long pc, int swi);

    /**
     * 返回<code>false</code>表示未处理的指令
     */
    boolean handleInterpreterFallback(long pc, int num_instructions);

    void handleExceptionRaised(long pc, int exception);

    void handleMemoryReadFailed(long vaddr, int size);
    void handleMemoryWriteFailed(long vaddr, int size);

}
