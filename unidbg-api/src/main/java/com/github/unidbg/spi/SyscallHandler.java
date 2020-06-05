package com.github.unidbg.spi;

import com.github.unidbg.Emulator;
import com.github.unidbg.debugger.Breaker;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.NewFileIO;
import unicorn.InterruptHook;

/**
 * syscall handler
 * Created by zhkl0228 on 2017/5/9.
 */

public interface SyscallHandler<T extends NewFileIO> extends InterruptHook {

    int DARWIN_SWI_SYSCALL = 0x80;

    /**
     * 后面添加的优先级高
     */
    void addIOResolver(IOResolver<T> resolver);

    int open(Emulator<T> emulator, String pathname, int oflags);

    void setVerbose(boolean verbose);
    boolean isVerbose();

    void setBreaker(Breaker breaker);

}
