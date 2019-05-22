package cn.banny.unidbg.hook.hookzz;

import cn.banny.unidbg.arm.RegisterContext;
import cn.banny.unidbg.spi.ValuePair;

import java.util.Map;

public abstract class HookZzRegisterContext implements RegisterContext, ValuePair {

    private final Map<String, Object> context;

    HookZzRegisterContext(Map<String, Object> context) {
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
