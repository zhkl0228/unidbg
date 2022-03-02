package com.github.unidbg.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalTask;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

abstract class AbstractTask extends BaseTask implements Task {

    private final int id;

    public AbstractTask(int id) {
        this.id = id;
    }

    private SigSet sigMaskSet;
    private SigSet sigPendingSet;

    @Override
    public SigSet getSigMaskSet() {
        return sigMaskSet;
    }

    @Override
    public SigSet getSigPendingSet() {
        return sigPendingSet;
    }

    @Override
    public void setSigMaskSet(SigSet sigMaskSet) {
        this.sigMaskSet = sigMaskSet;
    }

    @Override
    public void setSigPendingSet(SigSet sigPendingSet) {
        this.sigPendingSet = sigPendingSet;
    }

    @Override
    public int getId() {
        return id;
    }

    private final List<SignalTask> signalTaskList = new ArrayList<>();

    @Override
    public final void addSignalTask(SignalTask task) {
        signalTaskList.add(task);

        Waiter waiter = getWaiter();
        if (waiter != null) {
            waiter.onSignal(task);
        }
    }

    @Override
    public void removeSignalTask(SignalTask task) {
        signalTaskList.remove(task);
    }

    @Override
    public List<SignalTask> getSignalTaskList() {
        return signalTaskList.isEmpty() ? Collections.<SignalTask>emptyList() : new ArrayList<>(signalTaskList);
    }

    @Override
    public boolean setErrno(Emulator<?> emulator, int errno) {
        return false;
    }
}
