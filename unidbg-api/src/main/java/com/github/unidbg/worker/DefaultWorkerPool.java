package com.github.unidbg.worker;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

class DefaultWorkerPool implements WorkerPool, Runnable {

    private static final Log log = LogFactory.getLog(DefaultWorkerPool.class);

    private final BlockingQueue<Worker> releaseQueue = new LinkedBlockingQueue<>();
    private final BlockingQueue<Worker> workers;

    private final WorkerFactory factory;
    private final int workerCount;

    DefaultWorkerPool(WorkerFactory factory, int workerCount) {
        this.factory = factory;
        this.workerCount = workerCount;
        this.workers = new LinkedBlockingQueue<>(workerCount - 1);

        Thread thread = new Thread(this, "worker pool for " + factory);
        thread.start();
    }

    private boolean stopped;
    private int created;

    @Override
    public void run() {
        while (!stopped) {
            try {
                Worker release = created >= workerCount ? releaseQueue.poll(10, TimeUnit.MILLISECONDS) : releaseQueue.poll();
                if (release != null) {
                    workers.put(release);
                    continue;
                }

                if (created < workerCount) {
                    workers.put(factory.createWorker());
                    created++;
                }
            } catch (InterruptedException e) {
                log.warn("worker pool loop failed", e);
                break;
            }
        }

        closeWorkers(releaseQueue);
        closeWorkers(workers);
    }

    private static void closeWorkers(BlockingQueue<Worker> queue) {
        Worker worker;
        while ((worker = queue.poll()) != null) {
            IOUtils.closeQuietly(worker);
        }
    }

    @Override
    public void close() {
        stopped = true;

        closeWorkers(workers);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends Worker> T borrow(long timeout, TimeUnit unit) {
        if (stopped) {
            return null;
        }

        try {
            return (T) workers.poll(timeout, unit);
        } catch (InterruptedException e) {
            log.warn("borrow failed", e);
            return null;
        }
    }

    @Override
    public void release(Worker worker) {
        if (stopped) {
            IOUtils.closeQuietly(worker);
        } else {
            releaseQueue.offer(worker);
        }
    }

}
