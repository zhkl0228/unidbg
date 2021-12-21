package com.github.unidbg.ios.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.thread.Waiter;

import java.util.Map;

public class SemWaiter implements Waiter {

    private final int sem;
    private final Map<Integer, Boolean> semaphoreMap;

    public SemWaiter(int sem, Map<Integer, Boolean> semaphoreMap) {
        this.sem = sem;
        this.semaphoreMap = semaphoreMap;
    }

    @Override
    public boolean canDispatch() {
        Boolean val = semaphoreMap.remove(sem);
        return val != null;
    }

    @Override
    public void onContinueRun(Emulator<?> emulator) {
    }

}
