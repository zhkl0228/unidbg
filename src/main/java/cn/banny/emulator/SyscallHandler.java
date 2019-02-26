package cn.banny.emulator;

import cn.banny.emulator.linux.file.IOResolver;
import unicorn.InterruptHook;

/**
 * syscall handler
 * Created by zhkl0228 on 2017/5/9.
 */

public interface SyscallHandler extends InterruptHook {

    /**
     * 后面添加的优先级高
     */
    void addIOResolve(IOResolver resolver);

    int open(Emulator emulator, String pathname, int oflags);

}
