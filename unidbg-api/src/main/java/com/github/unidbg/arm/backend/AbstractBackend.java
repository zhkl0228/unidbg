package com.github.unidbg.arm.backend;

public abstract class AbstractBackend implements Backend {

    @Override
    public void onInitialize() {
    }

    @Override
    public int getPageSize() {
        return 0;
    }

}
