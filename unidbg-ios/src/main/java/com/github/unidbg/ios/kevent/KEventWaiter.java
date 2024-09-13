package com.github.unidbg.ios.kevent;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.thread.AbstractWaiter;
import com.github.unidbg.thread.Waiter;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class KEventWaiter extends AbstractWaiter implements Waiter {

    private static final Logger log = LoggerFactory.getLogger(KEventWaiter.class);

    private final KEvent event;
    private final Pointer eventlist;
    private final int nevents;

    public KEventWaiter(KEvent event, Pointer eventlist, int nevents) {
        this.event = event;
        this.eventlist = eventlist;
        this.nevents = nevents;
    }

    @Override
    public boolean canDispatch() {
        return !event.pendingEventList.isEmpty();
    }

    @Override
    public void onContinueRun(Emulator<?> emulator) {
        int size = UnidbgStructure.calculateSize(KEvent64.class);
        Pointer ptr = eventlist;
        int i = 0;
        for (; i < nevents && !event.pendingEventList.isEmpty(); i++, ptr = ptr.share(size)) {
            KEvent64 pending = event.pendingEventList.remove(0);
            KEvent64 kev = new KEvent64(ptr);
            kev.copy(pending);
            kev.pack();
            if (log.isDebugEnabled()) {
                log.debug("onContinueRun i={}, kev={}", i, kev);
            }
        }
        Backend backend = emulator.getBackend();
        if (emulator.is32Bit()) {
            backend.reg_write(ArmConst.UC_ARM_REG_R0, i);
        } else {
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, i);
        }
    }
}
