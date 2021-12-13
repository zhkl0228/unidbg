package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

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

    @Override
    public void addTask(Task task) {
        taskList.add(task);
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
                    if (task.canDispatch()) {
                        if (log.isDebugEnabled()) {
                            log.debug("Start dispatch task=" + task);
                        }
                        emulator.set(Task.TASK_KEY, task);
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
            }
        } finally {
            emulator.set(Task.TASK_KEY, null);
        }
    }

}
