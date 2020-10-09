package com.github.unidbg.arm.backend.dynarmic;

import com.github.unidbg.arm.backend.EventMemHook;

public class EventMemHookNotifier {

    private final EventMemHook callback;
    private final int type;
    private final Object user_data;

    public EventMemHookNotifier(EventMemHook callback, int type, Object user_data) {
        this.callback = callback;
        this.type = type;
        this.user_data = user_data;
    }

}
