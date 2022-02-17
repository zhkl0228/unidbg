package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.WriteHook;

class HypervisorWatchpoint {
    private final Object callback;
    private final long begin;
    private final long end;
    private final Object user_data;
    private final int n;
    private final boolean isWrite;

    public HypervisorWatchpoint(Object callback, long begin, long end, Object user_data, int n, boolean isWrite) {
        this.callback = callback;
        this.begin = begin;
        this.end = end;
        this.user_data = user_data;
        this.n = n;
        this.isWrite = isWrite;
    }

    public boolean contains(long address, boolean isWrite) {
        if (isWrite ^ this.isWrite) {
            return false;
        }
        return address >= begin && address < end;
    }

    public void onHit(Backend backend, long address, boolean isWrite) {
        if (isWrite) {
            ((WriteHook) callback).hook(backend, address, 0, 0, user_data);
        } else {
            ((ReadHook) callback).hook(backend, address, 0, user_data);
        }
    }

    public void install(Hypervisor hypervisor) {
        hypervisor.install_watchpoint(n, begin, end, isWrite);
    }
}
