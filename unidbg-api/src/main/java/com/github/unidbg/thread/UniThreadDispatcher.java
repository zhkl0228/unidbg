package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.SignalTask;
import com.github.unidbg.signal.UnixSigSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 抢占式调度
 */
public class UniThreadDispatcher implements ThreadDispatcher {

    private static final Logger log = LoggerFactory.getLogger(UniThreadDispatcher.class);

    private final List<Task> taskList = new ArrayList<>();
    private final AbstractEmulator<?> emulator;

    public UniThreadDispatcher(AbstractEmulator<?> emulator) {
        this.emulator = emulator;
    }

    private final List<ThreadTask> threadTaskList = new ArrayList<>();

    @Override
    public void addThread(ThreadTask task) {
        threadTaskList.add(task);
    }

    @Override
    public List<Task> getTaskList() {
        return taskList;
    }

    @Override
    public boolean sendSignal(int tid, int sig, SignalTask signalTask) {
        List<Task> list = new ArrayList<>();
        list.addAll(taskList);
        list.addAll(threadTaskList);
        boolean ret = false;
        for (Task task : list) {
            SignalOps signalOps = null;
            if (tid == 0 && task.isMainThread()) {
                signalOps = this;
            }
            if (tid == task.getId()) {
                signalOps = task;
            }
            if (signalOps == null) {
                continue;
            }
            SigSet sigSet = signalOps.getSigMaskSet();
            SigSet sigPendingSet = signalOps.getSigPendingSet();
            if (sigPendingSet == null) {
                sigPendingSet = new UnixSigSet(0);
                signalOps.setSigPendingSet(sigPendingSet);
            }
            if (sigSet != null && sigSet.containsSigNumber(sig)) {
                sigPendingSet.addSigNumber(sig);
                return false;
            }
            if (signalTask != null) {
                task.addSignalTask(signalTask);
                if (log.isTraceEnabled()) {
                    emulator.attach().debug();
                }
            } else {
                sigPendingSet.addSigNumber(sig);
            }
            ret = true;
            break;
        }
        return ret;
    }

    private RunnableTask runningTask;

    @Override
    public RunnableTask getRunningTask() {
        return runningTask;
    }

    @Override
    public Number runMainForResult(MainTask main) {
        taskList.add(0, main);

        log.debug("runMainForResult main={}", main);

        Number ret = run(0, null);
        for (Iterator<Task> iterator = taskList.iterator(); iterator.hasNext(); ) {
            Task task = iterator.next();
            if (task.isFinish()) {
                log.debug("Finish task={}", task);
                task.destroy(emulator);
                iterator.remove();
                for (SignalTask signalTask : task.getSignalTaskList()) {
                    signalTask.destroy(emulator);
                    task.removeSignalTask(signalTask);
                }
            }
        }
        return ret;
    }

    @Override
    public void runThreads(long timeout, TimeUnit unit) {
        if (timeout <= 0 || unit == null) {
            throw new IllegalArgumentException("Invalid timeout.");
        }
        run(timeout, unit);
    }

    private Number run(long timeout, TimeUnit unit) {
        try {
            long start = System.currentTimeMillis();
            while (true) {
                if (taskList.isEmpty()) {
                    throw new IllegalStateException();
                }
                for (Iterator<Task> iterator = taskList.iterator(); iterator.hasNext(); ) {
                    Task task = iterator.next();
                    if (task.isFinish()) {
                        continue;
                    }
                    if (task.canDispatch()) {
                        log.debug("Start dispatch task={}", task);
                        emulator.set(Task.TASK_KEY, task);

                        if(task.isContextSaved()) {
                            task.restoreContext(emulator);
                            for (SignalTask signalTask : task.getSignalTaskList()) {
                                if (signalTask.canDispatch()) {
                                    log.debug("Start run signalTask={}", signalTask);
                                    SignalOps ops = task.isMainThread() ? this : task;
                                    try {
                                        this.runningTask = signalTask;
                                        Number ret = signalTask.callHandler(ops, emulator);
                                        log.debug("End run signalTask={}, ret={}", signalTask, ret);
                                        if (ret != null) {
                                            signalTask.setResult(emulator, ret);
                                            signalTask.destroy(emulator);
                                            task.removeSignalTask(signalTask);
                                        } else {
                                            signalTask.saveContext(emulator);
                                        }
                                    } catch (PopContextException e) {
                                        this.runningTask.popContext(emulator);
                                    }
                                } else {
                                    log.debug("Skip call handler signalTask={}", signalTask);
                                }
                            }
                        }

                        try {
                            this.runningTask = task;
                            Number ret = task.dispatch(emulator);
                            log.debug("End dispatch task={}, ret={}", task, ret);
                            if (ret != null) {
                                task.setResult(emulator, ret);
                                task.destroy(emulator);
                                iterator.remove();
                                if(task.isMainThread()) {
                                    return ret;
                                }
                            } else {
                                task.saveContext(emulator);
                            }
                        } catch(PopContextException e) {
                            this.runningTask.popContext(emulator);
                        }
                    } else {
                        if (log.isTraceEnabled() && task.isContextSaved()) {
                            task.restoreContext(emulator);
                            log.trace("Skip dispatch task={}", task);
                            emulator.getUnwinder().unwind();
                        } else {
                            log.debug("Skip dispatch task={}", task);
                        }
                    }
                }

                Collections.reverse(threadTaskList);
                for (Iterator<ThreadTask> iterator = threadTaskList.iterator(); iterator.hasNext(); ) {
                    taskList.add(0, iterator.next());
                    iterator.remove();
                }

                if (timeout > 0 && unit != null &&
                        System.currentTimeMillis() - start >= unit.toMillis(timeout)) {
                    return null;
                }
                if (taskList.isEmpty()) {
                    return null;
                }

                if (log.isDebugEnabled()) {
                    try {
                        TimeUnit.SECONDS.sleep(1);
                    } catch (InterruptedException ignored) {
                    }
                }
            }
        } finally {
            this.runningTask = null;
            emulator.set(Task.TASK_KEY, null);
        }
    }

    @Override
    public int getTaskCount() {
        return taskList.size() + threadTaskList.size();
    }

    private SigSet mainThreadSigMaskSet;
    private SigSet mainThreadSigPendingSet;

    @Override
    public SigSet getSigMaskSet() {
        return mainThreadSigMaskSet;
    }

    @Override
    public void setSigMaskSet(SigSet sigMaskSet) {
        this.mainThreadSigMaskSet = sigMaskSet;
    }

    @Override
    public SigSet getSigPendingSet() {
        return mainThreadSigPendingSet;
    }

    @Override
    public void setSigPendingSet(SigSet sigPendingSet) {
        this.mainThreadSigPendingSet = sigPendingSet;
    }
}
