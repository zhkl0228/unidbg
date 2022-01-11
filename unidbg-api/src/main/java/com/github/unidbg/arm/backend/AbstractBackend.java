package com.github.unidbg.arm.backend;

public abstract class AbstractBackend implements Backend {

    @Override
    public void onInitialize() {
    }

    @Override
    public int getPageSize() {
        return 0;
    }

    @Override
    public void registerEmuCountHook(long emu_count) {
        throw new UnsupportedOperationException();
    }

}
