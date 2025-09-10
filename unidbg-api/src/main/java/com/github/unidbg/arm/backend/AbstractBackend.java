package com.github.unidbg.arm.backend;

import java.util.Collections;
import java.util.Map;

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

    @Override
    public void removeJitCodeCache(long begin, long end) throws BackendException {
    }

    @Override
    public Map<String, Integer> getCpuFeatures() {
        return Collections.emptyMap();
    }

}
