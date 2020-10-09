package com.github.unidbg.arm.backend.dynarmic;

import com.github.unidbg.arm.backend.InterruptHook;

public class InterruptHookNotifier {

    private final InterruptHook callback;
    private final Object user_data;

    public InterruptHookNotifier(InterruptHook callback, Object user_data) {
        this.callback = callback;
        this.user_data = user_data;
    }

}
