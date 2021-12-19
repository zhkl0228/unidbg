package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.SignalTask;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 抢占式调度
 */
public class UniThreadDispatcher implements ThreadDispatcher {

    private static final Log log = LogFactory.getLog(UniThreadDispatcher.class);

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
    public boolean sendSignal(int tid, SignalTask signalTask) {
        List<Task> list = new ArrayList<>();
        list.addAll(taskList);
        list.addAll(threadTaskList);
        boolean ret = false;
        for (Task task : list) {
            if (tid == 0 && task.isMainThread()) {
                if (mainThreadSigMaskSet != null && mainThreadSigMaskSet.containsSigNumber(signalTask.getSigNumber())) {
                    if (mainThreadSigPendingSet != null) {
                        mainThreadSigPendingSet.addSigNumber(signalTask.getSigNumber());
                    }
                    return false;
                }
                task.addSignalTask(signalTask);
                ret = true;
                break;
            }
            if (tid == task.getId()) {
                SigSet sigSet = task.getSigMaskSet();
                if (sigSet != null && sigSet.containsSigNumber(signalTask.getSigNumber())) {
                    SigSet sigPendingSet = task.getSigPendingSet();
                    if (sigPendingSet != null) {
                        sigPendingSet.addSigNumber(signalTask.getSigNumber());
                    }
                    return false;
                }
                task.addSignalTask(signalTask);
                ret = true;
                break;
            }
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

        if (log.isDebugEnabled()) {
            log.debug("runMainForResult main=" + main);
        }

        try {
            while (true) {
                if (taskList.isEmpty()) {
                    throw new IllegalStateException();
                }
                for (Iterator<Task> iterator = taskList.iterator(); iterator.hasNext(); ) {
                    Task task = iterator.next();
                    if (task.isFinish()) {
                        if (log.isDebugEnabled()) {
                            log.debug("Finish task=" + task);
                        }
                        task.destroy(emulator);
                        iterator.remove();
                        for (SignalTask signalTask : task.getSignalTaskList()) {
                            signalTask.destroy(emulator);
                            task.removeSignalTask(signalTask);
                        }
                        continue;
                    }
                    if (task.canDispatch()) {
                        if (log.isDebugEnabled()) {
                            log.debug("Start dispatch task=" + task);
                        }
                        emulator.set(Task.TASK_KEY, task);

                        if(task.isContextSaved()) {
                            task.restoreContext(emulator);
                            for (SignalTask signalTask : task.getSignalTaskList()) {
                                if (signalTask.canDispatch()) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Start run signalTask=" + signalTask);
                                    }
                                    SignalOps ops = task.isMainThread() ? this : task;
                                    this.runningTask = signalTask;
                                    Number ret = signalTask.callHandler(ops, emulator);
                                    if (log.isDebugEnabled()) {
                                        log.debug("End run signalTask=" + signalTask + ", ret=" + ret);
                                    }
                                    if (ret != null) {
                                        signalTask.destroy(emulator);
                                        task.removeSignalTask(signalTask);
                                    } else {
                                        signalTask.saveContext(emulator);
                                    }
                                } else if (log.isDebugEnabled()) {
                                    log.debug("Skip call handler signalTask=" + signalTask);
                                }
                            }
                        }

                        this.runningTask = task;
                        Number ret = task.dispatch(emulator);
                        if (log.isDebugEnabled()) {
                            log.debug("End dispatch task=" + task + ", ret=" + ret);
                        }
                        if (ret != null) {
                            task.destroy(emulator);
                            iterator.remove();
                            if(task.isMainThread()) {
                                return ret;
                            }
                        } else {
                            task.saveContext(emulator);
                        }
                    } else if (log.isDebugEnabled()) {
                        log.debug("Skip dispatch task=" + task);
                    }
                }

                Collections.reverse(threadTaskList);
                for (Iterator<ThreadTask> iterator = threadTaskList.iterator(); iterator.hasNext(); ) {
                    taskList.add(0, iterator.next());
                    iterator.remove();
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
