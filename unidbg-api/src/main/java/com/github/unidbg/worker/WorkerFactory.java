package com.github.unidbg.worker;

/**
 * Worker 工厂接口，用于创建新的 {@link Worker} 实例。
 *
 * <p>典型用法是通过方法引用传递给 {@link WorkerPoolFactory#create}：</p>
 * <pre>{@code
 * WorkerPool pool = WorkerPoolFactory.create(MyWorker::new, 4);
 * }</pre>
 *
 * @see WorkerPoolFactory
 */
public interface WorkerFactory {

    /**
     * 创建一个新的 Worker 实例。
     *
     * @return 新创建的 Worker
     */
    Worker createWorker();

}
