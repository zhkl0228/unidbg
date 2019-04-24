package cn.banny.emulator.spi;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.file.IOResolver;
import unicorn.InterruptHook;

/**
 * syscall handler
 * Created by zhkl0228 on 2017/5/9.
 */

public interface SyscallHandler extends InterruptHook {

    /**
     * 后面添加的优先级高
     */
    void addIOResolver(IOResolver resolver);

    int open(Emulator emulator, String pathname, int oflags);

}
