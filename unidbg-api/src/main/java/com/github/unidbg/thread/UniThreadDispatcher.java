package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
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
                    if (task.isDead()) {
                        task.destroy(emulator);
                        iterator.remove();
                        for (Task signalTask : task.getSignalTaskList()) {
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

                        for (Task signalTask : task.getSignalTaskList()) {
                            if (log.isDebugEnabled()) {
                                log.debug("Start dispatch signalTask=" + signalTask);
                            }
                            Number ret = signalTask.dispatch(emulator);
                            if (log.isDebugEnabled()) {
                                log.debug("End dispatch signalTask=" + signalTask + ", ret=" + ret);
                            }
                            if (ret != null) {
                                signalTask.destroy(emulator);
                                task.removeSignalTask(signalTask);
                            } else {
                                throw new UnsupportedOperationException();
                            }
                        }

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
            emulator.set(Task.TASK_KEY, null);
        }
    }

    @Override
    public int getTaskCount() {
        return taskList.size();
    }
}
