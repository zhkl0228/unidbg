package com.github.unidbg.arm.backend;

abstract class AbstractBackend implements Backend {

    @Override
    public void onInitialize() {
    }

    @Override
    public int getPageSize() {
        return 0;
    }

}
