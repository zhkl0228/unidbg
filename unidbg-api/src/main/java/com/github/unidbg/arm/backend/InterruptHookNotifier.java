package com.github.unidbg.arm.backend;

public class InterruptHookNotifier {

    private final InterruptHook callback;
    private final Object user_data;

    public InterruptHookNotifier(InterruptHook callback, Object user_data) {
        this.callback = callback;
        this.user_data = user_data;
    }

    public void notifyCallSVC(Backend backend, int intno, int swi) {
        callback.hook(backend, intno, swi, user_data);
    }

}
