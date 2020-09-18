package com.github.unidbg.unix;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileIO;

public interface FileListener {

    void onOpenSuccess(Emulator<?> emulator, String pathname, FileIO io);

    void onClose(Emulator<?> emulator, FileIO io);

}
