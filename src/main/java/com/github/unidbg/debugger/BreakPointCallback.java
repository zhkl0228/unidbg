package com.github.unidbg.debugger;

import com.github.unidbg.Emulator;

public interface BreakPointCallback {

    /**
     * 当断点被触发时回调
     * @return 返回<code>false</code>表示断点成功，返回<code>true</code>表示不触发断点，继续进行
     */
    boolean onHit(Emulator<?> emulator, long address);

}
