package com.github.unidbg.unix;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileIO;
import com.sun.jna.Pointer;

public interface FileListener {

    void onOpenSuccess(Emulator<?> emulator, String pathname, FileIO io);

    void onRead(Emulator<?> emulator, String pathname, Pointer buffer, byte[] bytes);
    void onWrite(Emulator<?> emulator, String pathname, Pointer buffer, byte[] bytes);

    void onClose(Emulator<?> emulator, FileIO io);

}
