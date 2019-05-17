package cn.banny.unidbg.spi;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.file.IOResolver;
import unicorn.InterruptHook;

/**
 * syscall handler
 * Created by zhkl0228 on 2017/5/9.
 */

public interface SyscallHandler extends InterruptHook {

    int DARWIN_SWI_SYSCALL = 0x80;

    /**
     * 后面添加的优先级高
     */
    void addIOResolver(IOResolver resolver);

    int open(Emulator emulator, String pathname, int oflags);

}
