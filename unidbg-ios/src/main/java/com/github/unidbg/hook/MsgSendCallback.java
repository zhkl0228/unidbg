package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.sun.jna.Pointer;

public interface MsgSendCallback {

    void onMsgSend(Emulator<?> emulator, boolean systemClass, String className, String cmd, Pointer lr);

}
