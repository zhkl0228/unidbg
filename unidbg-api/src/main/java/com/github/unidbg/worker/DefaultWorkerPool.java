package com.github.unidbg.worker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * {@link WorkerPool} 的默认实现，使用独立线程管理 Worker 的创建、回收与空闲清理。
 *
 * <ul>
 *   <li>Worker 按需创建：只有当可用池为空且未达到上限时，才创建新的 Worker</li>
 *   <li>总 Worker 数量（借出 + 空闲）不超过 {@code maxWorkers}</li>
 *   <li>空闲超过 {@code idleTimeout} 的 Worker 由管理线程自动销毁</li>
 * </ul>
 *
 * <p>内部维护两个队列：
 * <ul>
 *   <li>{@code workers} — 可供借出的空闲 Worker 队列</li>
 *   <li>{@code releaseQueue} — 归还缓冲队列，由管理线程转入 workers</li>
 * </ul>
 */
class DefaultWorkerPool implements WorkerPool, Runnable {

    private static final Logger log = LoggerFactory.getLogger(DefaultWorkerPool.class);

    private static final int MIN_IDLE_TIMEOUT_MINUTES = 1;
    private static final int DEFAULT_IDLE_TIMEOUT_MINUTES = 10;
    private static final long CLEANUP_INTERVAL_MS = 30_000;

    /**
     * 包装空闲 Worker，记录入池时间以便判定超时。
     * 使用 {@link System#currentTimeMillis()} 而非 nanoTime，
     * 因为 nanoTime 在 macOS 系统休眠期间不推进，会导致空闲超时失效。
     */
    private static class IdleWorker {
        final Worker worker;
        final long idleSinceMs;

        IdleWorker(Worker worker) {
            this.worker = worker;
            this.idleSinceMs = System.currentTimeMillis();
        }
    }

    private final BlockingQueue<IdleWorker> workers = new LinkedBlockingQueue<>();
    private final BlockingQueue<Worker> releaseQueue = new LinkedBlockingQueue<>();
    private final AtomicInteger totalAlive = new AtomicInteger();

    private final WorkerFactory factory;
    private final int maxWorkers;
    private volatile long idleTimeoutMs = TimeUnit.MINUTES.toMillis(DEFAULT_IDLE_TIMEOUT_MINUTES);
    private volatile int minIdle = 1;

    private final Thread thread;
    private volatile boolean stopped;

    DefaultWorkerPool(WorkerFactory factory, int maxWorkers) {
        if (maxWorkers <= 0) {
            throw new IllegalArgumentException("maxWorkers must be positive: " + maxWorkers);
        }

        log.info("Creating worker pool: factory={}, maxWorkers={}, idleTimeout={}min", factory, maxWorkers, DEFAULT_IDLE_TIMEOUT_MINUTES);
        this.factory = factory;
        this.maxWorkers = maxWorkers;

        this.thread = new Thread(this, "worker pool for " + factory);
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void setIdleTimeout(int idleTimeoutMinutes) {
        if (idleTimeoutMinutes < MIN_IDLE_TIMEOUT_MINUTES) {
            throw new IllegalArgumentException("idleTimeoutMinutes must be at least " + MIN_IDLE_TIMEOUT_MINUTES + ": " + idleTimeoutMinutes);
        }
        this.idleTimeoutMs = TimeUnit.MINUTES.toMillis(idleTimeoutMinutes);
        log.debug("Updated idle timeout: {}min", idleTimeoutMinutes);
    }

    @Override
    public void setMinIdle(int minIdle) {
        if (minIdle < 1) {
            throw new IllegalArgumentException("minIdle must be at least 1: " + minIdle);
        }
        this.minIdle = minIdle;
        log.debug("Updated minIdle: {}", minIdle);
    }

    /**
     * 管理线程主循环：按需创建 Worker、处理归还、清理空闲超时 Worker。
     */
    @Override
    public void run() {
        long lastCleanupMs = System.currentTimeMillis();

        while (!stopped) {
            try {
                boolean shouldCreate = workers.isEmpty() && totalAlive.get() < maxWorkers;

                Worker release = shouldCreate
                        ? releaseQueue.poll()
                        : releaseQueue.poll(1, TimeUnit.SECONDS);

                if (release != null) {
                    if (!workers.offer(new IdleWorker(release))) {
                        throw new IllegalStateException("Offer released worker failed.");
                    }
                    continue;
                }

                if (shouldCreate) {
                    totalAlive.incrementAndGet();
                    long startMs = System.currentTimeMillis();
                    Worker worker;
                    try {
                        worker = factory.createWorker();
                    } catch (RuntimeException e) {
                        totalAlive.decrementAndGet();
                        log.warn("Failed to create worker", e);
                        continue;
                    }
                    log.info("Created new worker: {}, totalAlive={}/{}, elapsed={}ms", worker, totalAlive.get(), maxWorkers, System.currentTimeMillis() - startMs);
                    if (!workers.offer(new IdleWorker(worker))) {
                        throw new IllegalStateException("Offer created worker failed.");
                    }
                    continue;
                }

                long now = System.currentTimeMillis();
                if (now - lastCleanupMs >= CLEANUP_INTERVAL_MS) {
                    lastCleanupMs = now;
                    int size = workers.size();
                    for (int i = 0; i < size; i++) {
                        IdleWorker idle = workers.poll();
                        if (idle == null) break;
                        if (now - idle.idleSinceMs > idleTimeoutMs && totalAlive.get() > minIdle) {
                            idle.worker.destroy();
                            int remaining = totalAlive.decrementAndGet();
                            log.info("Destroyed idle worker: {}, totalAlive={}", idle.worker, remaining);
                        } else if (!workers.offer(idle)) {
                            throw new IllegalStateException("Offer idle worker failed.");
                        }
                    }
                }
            } catch (InterruptedException e) {
                if (!stopped) {
                    log.warn("worker pool thread interrupted unexpectedly", e);
                }
                break;
            }
        }

        closeIdleWorkers();
        closeReleasedWorkers();
    }

    private void closeIdleWorkers() {
        IdleWorker idle;
        while ((idle = workers.poll()) != null) {
            idle.worker.destroy();
            log.info("Closed idle worker: {}", idle.worker);
        }
    }

    private void closeReleasedWorkers() {
        Worker worker;
        while ((worker = releaseQueue.poll()) != null) {
            worker.destroy();
            log.info("Closed released worker: {}", worker);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends Worker> WorkerLoan<T> borrow(long timeout, TimeUnit unit) {
        if (stopped) {
            return null;
        }

        try {
            IdleWorker idle = workers.poll(timeout, unit);
            return idle == null ? null : new WorkerLoan<>((T) idle.worker, this);
        } catch (InterruptedException e) {
            log.warn("borrow interrupted", e);
            return null;
        }
    }

    /**
     * 归还 Worker 到 releaseQueue，由管理线程转入可用池。
     * 池已关闭时直接销毁。
     */
    @Override
    public void release(Worker worker) {
        if (stopped) {
            worker.destroy();
            totalAlive.decrementAndGet();
        } else if (!releaseQueue.offer(worker)) {
            throw new IllegalStateException("Release worker failed.");
        }
    }

    @Override
    public void close() {
        stopped = true;
        try {
            thread.join(5000);
        } catch (InterruptedException e) {
            log.warn("close interrupted while waiting for worker pool thread", e);
        }

        closeIdleWorkers();
        closeReleasedWorkers();
    }

}
