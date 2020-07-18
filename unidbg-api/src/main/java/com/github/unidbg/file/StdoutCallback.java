package com.github.unidbg.file;

public interface StdoutCallback {

    void notifyOut(byte[] data, boolean err);

}
