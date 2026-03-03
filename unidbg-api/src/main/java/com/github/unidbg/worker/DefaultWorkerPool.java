package com.github.unidbg.worker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * {@link WorkerPool} 的默认实现，使用独立线程管理 Worker 的创建与回收。
 *
 * <p>内部维护两个队列：
 * <ul>
 *   <li>{@code workers} — 可供借出的 Worker 队列，容量等于 workerCount</li>
 *   <li>{@code releaseQueue} — 归还缓冲队列，用于在 workers 队列满时暂存归还的 Worker</li>
 * </ul>
 *
 * <p>管理线程负责：按需创建 Worker（最多 workerCount 个），
 * 以及将 releaseQueue 中的 Worker 移回 workers 队列。</p>
 */
class DefaultWorkerPool implements WorkerPool, Runnable {

    private static final Logger log = LoggerFactory.getLogger(DefaultWorkerPool.class);

    private final BlockingQueue<Worker> releaseQueue = new LinkedBlockingQueue<>();
    private final BlockingQueue<Worker> workers;

    private final WorkerFactory factory;
    private final int workerCount;

    DefaultWorkerPool(WorkerFactory factory, int workerCount) {
        if (workerCount <= 0) {
            throw new IllegalArgumentException("workerCount must be positive: " + workerCount);
        }

        log.debug("Creating worker pool: factory={}, workerCount={}", factory, workerCount);
        this.factory = factory;
        this.workerCount = workerCount;
        this.workers = new LinkedBlockingQueue<>(workerCount);

        this.thread = new Thread(this, "worker pool for " + factory);
        thread.start();
    }

    private final Thread thread;
    private volatile boolean stopped;
    /** 仅由管理线程访问，无需同步 */
    private int created;

    /**
     * 管理线程主循环：创建 Worker 并处理归还请求。
     * 通过 volatile {@code stopped} 标志控制退出，退出后销毁所有残留 Worker。
     */
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
                if (!stopped) {
                    log.warn("worker pool loop interrupted unexpectedly", e);
                }
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

    /**
     * 关闭池：设置停止标志，等待管理线程退出，然后兜底清理残留 Worker。
     */
    @Override
    public void close() {
        stopped = true;
        try {
            thread.join(5000);
        } catch (InterruptedException e) {
            log.warn("close interrupted while waiting for worker pool thread", e);
        }
        closeWorkers(releaseQueue);
        closeWorkers(workers);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends Worker> WorkerLoan<T> borrow(long timeout, TimeUnit unit) {
        if (stopped) {
            return null;
        }

        try {
            Worker worker = workers.poll(timeout, unit);
            return worker == null ? null : new WorkerLoan<>((T) worker, this);
        } catch (InterruptedException e) {
            log.warn("borrow failed", e);
            return null;
        }
    }

    /**
     * 归还 Worker。优先直接放回 workers 队列，队列满时暂存到 releaseQueue。
     * 池已关闭时直接销毁 Worker。
     */
    @Override
    public void release(Worker worker) {
        if (stopped) {
            worker.destroy();
        } else if (!workers.offer(worker)) {
            if (!releaseQueue.offer(worker)) {
                throw new IllegalStateException("Release worker failed.");
            }
        }
    }

}
