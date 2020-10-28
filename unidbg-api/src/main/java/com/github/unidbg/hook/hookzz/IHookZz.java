package com.github.unidbg.hook.hookzz;

import com.github.unidbg.Symbol;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.IHook;
import com.github.unidbg.hook.ReplaceCallback;

public interface IHookZz extends IHook {

    void enable_arm_arm64_b_branch();
    void disable_arm_arm64_b_branch();

    void switch_to_file_log(String path);

    <T extends RegisterContext> void wrap(long functionAddress, WrapCallback<T> callback);
    <T extends RegisterContext> void wrap(Symbol symbol, WrapCallback<T> callback);

    void replace(long functionAddress, ReplaceCallback callback);
    void replace(Symbol symbol, ReplaceCallback callback);

    void replace(long functionAddress, ReplaceCallback callback, boolean enablePostCall);
    void replace(Symbol symbol, ReplaceCallback callback, boolean enablePostCall);

    <T extends RegisterContext> void instrument(long functionAddress, InstrumentCallback<T> callback);
    <T extends RegisterContext> void instrument(Symbol symbol, InstrumentCallback<T> callback);

}
