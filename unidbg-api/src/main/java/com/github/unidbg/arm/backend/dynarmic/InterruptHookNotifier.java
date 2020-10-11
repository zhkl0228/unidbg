package com.github.unidbg.arm.backend.dynarmic;

import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.InterruptHook;

public class InterruptHookNotifier {

    private final InterruptHook callback;
    private final Object user_data;

    public InterruptHookNotifier(InterruptHook callback, Object user_data) {
        this.callback = callback;
        this.user_data = user_data;
    }

    public void notifyCallSVC(Backend backend) {
        callback.hook(backend, ARMEmulator.EXCP_SWI, user_data);
    }

}
