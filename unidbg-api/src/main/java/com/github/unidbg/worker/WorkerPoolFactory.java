package com.github.unidbg.worker;

import org.scijava.nativelib.NativeLibraryUtil;

/**
 * {@link WorkerPool} 的静态工厂类。
 *
 * <pre>{@code
 * // 基本用法
 * WorkerPool pool = WorkerPoolFactory.create(MyWorker::new, 4);
 *
 * // 使用 unicorn1 backend 时，在 Apple Silicon 上自动限制为单 worker
 * WorkerPool pool = WorkerPoolFactory.create(MyWorker::new, 4, true);
 * }</pre>
 */
public class WorkerPoolFactory {

    /**
     * 创建一个包含指定数量 Worker 的对象池。
     *
     * @param factory     用于创建 Worker 的工厂
     * @param workerCount Worker 数量（必须 &gt; 0）
     * @return 新创建的 WorkerPool
     */
    public static WorkerPool create(WorkerFactory factory, int workerCount) {
        return create(factory, workerCount, false);
    }

    /**
     * 创建一个包含指定数量 Worker 的对象池。
     *
     * @param factory          用于创建 Worker 的工厂
     * @param workerCount      Worker 数量（必须 &gt; 0）
     * @param unicorn1Backend  是否使用 unicorn1 backend；为 {@code true} 时，
     *                         在 Apple Silicon (M1/M2) 上自动将 workerCount 限制为 1
     * @return 新创建的 WorkerPool
     */
    public static WorkerPool create(WorkerFactory factory, int workerCount, boolean unicorn1Backend) {
        if (unicorn1Backend &&
                NativeLibraryUtil.getArchitecture() == NativeLibraryUtil.Architecture.OSX_ARM64 &&
                workerCount > 1) {
            workerCount = 1;
        }
        return new DefaultWorkerPool(factory, workerCount);
    }

}
