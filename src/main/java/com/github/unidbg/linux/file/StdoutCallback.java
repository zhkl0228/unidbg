package com.github.unidbg.linux.file;

public interface StdoutCallback {

    void notifyOut(byte[] data, boolean err);

}
