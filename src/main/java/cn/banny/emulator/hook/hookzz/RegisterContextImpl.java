package cn.banny.emulator.hook.hookzz;

import java.util.Map;

public abstract class RegisterContextImpl implements RegisterContext {

    private final Map<String, Object> context;

    RegisterContextImpl(Map<String, Object> context) {
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
