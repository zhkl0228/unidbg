package com.github.unidbg.hook;

import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.spi.ValuePair;

import java.util.Map;

public abstract class HookContext implements RegisterContext, ValuePair {

    private final Map<String, Object> context;

    HookContext(Map<String, Object> context) {
        this.context = context;
    }

    @Override
    public void set(String key, Object value) {
        context.put(key, value);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T get(String key) {
        return (T) context.get(key);
    }

}
