package com.github.unidbg.worker;

import org.scijava.nativelib.NativeLibraryUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

class DefaultWorkerPool implements WorkerPool, Runnable {

    private static final Logger log = LoggerFactory.getLogger(DefaultWorkerPool.class);

    private final BlockingQueue<Worker> releaseQueue = new LinkedBlockingQueue<>();
    private final BlockingQueue<Worker> workers;

    private final WorkerFactory factory;
    private final int workerCount;

    DefaultWorkerPool(WorkerFactory factory, int workerCount) {
        if (NativeLibraryUtil.getArchitecture() == NativeLibraryUtil.Architecture.OSX_ARM64 && workerCount > 1) { // bug fix: unicorn backend for m1
            workerCount = 1;
        }

        this.factory = factory;
        this.workerCount = workerCount;
        this.workers = new LinkedBlockingQueue<>(workerCount == 1 ? 1 : workerCount - 1);

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
                    workers.put(factory.createWorker(this));
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
            worker.destroy();
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
            worker.destroy();
        } else {
            if (!releaseQueue.offer(worker)) {
                throw new IllegalStateException("Release worker failed.");
            }
        }
    }

}
