package com.github.unidbg.memory;

public interface MMapListener {

    void onMap(long address, long size, int perms);

    void onProtect(long address, long size, int perms);

    void onUnmap(long address, long size);

}
