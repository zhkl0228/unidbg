package com.github.unidbg.worker;

import org.scijava.nativelib.NativeLibraryUtil;

/**
 * {@link WorkerPool} 的静态工厂类。
 *
 * <p>池采用懒初始化策略：Worker 按需创建，空闲超时后自动销毁。
 * 可通过 {@link WorkerPool#setIdleTimeout} 自定义空闲超时（默认 10 分钟）。</p>
 *
 * <pre>{@code
 * // 使用 CPU 核心数作为最大 Worker 数量
 * WorkerPool pool = WorkerPoolFactory.create(MyWorker::new);
 *
 * // 指定最大 Worker 数量
 * WorkerPool pool = WorkerPoolFactory.create(MyWorker::new, 4);
 *
 * // 使用 unicorn1 backend 时，在 Apple Silicon 上自动限制为单 worker
 * WorkerPool pool = WorkerPoolFactory.create(MyWorker::new, 4, true);
 *
 * // 自定义空闲超时
 * WorkerPool pool = WorkerPoolFactory.create(MyWorker::new);
 * pool.setIdleTimeout(30); // 30 分钟
 *
 * // 预创建初始 Worker
 * WorkerPool pool = WorkerPoolFactory.create(MyWorker::new, 8);
 * pool.setInitialSize(4); // 启动时预创建 4 个 Worker
 * }</pre>
 */
public class WorkerPoolFactory {

    /**
     * 创建一个 Worker 对象池，使用当前 CPU 核心数作为最大 Worker 数量。
     *
     * @param factory 用于创建 Worker 的工厂
     * @return 新创建的 WorkerPool
     */
    public static WorkerPool create(WorkerFactory factory) {
        return create(factory, Runtime.getRuntime().availableProcessors());
    }

    /**
     * 创建一个 Worker 对象池，最多包含 {@code workerCount} 个 Worker。
     *
     * @param factory     用于创建 Worker 的工厂
     * @param workerCount 最大 Worker 数量（必须 &gt; 0）
     * @return 新创建的 WorkerPool
     */
    public static WorkerPool create(WorkerFactory factory, int workerCount) {
        return create(factory, workerCount, false);
    }

    /**
     * 创建一个 Worker 对象池，使用默认空闲超时（10 分钟）。
     *
     * @param factory          用于创建 Worker 的工厂
     * @param workerCount      最大 Worker 数量（必须 &gt; 0）
     * @param hypervisorBackend  是否使用 hypervisor backend；为 {@code true} 时，
     *                         在 Apple Silicon (M1/M2) 上自动将 workerCount 限制为 1
     * @return 新创建的 WorkerPool
     */
    public static WorkerPool create(WorkerFactory factory, int workerCount, boolean hypervisorBackend) {
        if (hypervisorBackend &&
                NativeLibraryUtil.getArchitecture() == NativeLibraryUtil.Architecture.OSX_ARM64 &&
                workerCount > 1) {
            workerCount = 1;
        }
        return new DefaultWorkerPool(factory, workerCount);
    }

}
