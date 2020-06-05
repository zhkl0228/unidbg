package com.github.unidbg.hook;

import com.github.unidbg.memory.SvcMemory;

public interface HookListener {

    /**
     * 返回0表示没有hook，否则返回hook以后的调用地址
     */
    long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old);

}
