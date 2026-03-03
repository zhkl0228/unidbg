package com.github.unidbg.worker;

import java.io.Closeable;
import java.util.concurrent.TimeUnit;

/**
 * Worker 对象池接口，管理一组可复用 Worker 的借出与归还。
 *
 * <p>通过 {@link WorkerPoolFactory#create} 创建实例。
 * 池关闭时会销毁所有托管的 Worker。</p>
 *
 * @see WorkerPoolFactory
 * @see WorkerLoan
 */
public interface WorkerPool extends Closeable {

    /**
     * 从池中借出一个 Worker，返回 {@link WorkerLoan} 包装器。
     *
     * @param timeout 等待超时时长
     * @param unit    超时时间单位
     * @param <T>     Worker 的具体类型
     * @return WorkerLoan 包装器，超时或池已关闭时返回 {@code null}
     */
    <T extends Worker> WorkerLoan<T> borrow(long timeout, TimeUnit unit);

    /**
     * 将 Worker 归还到池中。通常不需要直接调用，
     * 由 {@link WorkerLoan#close()} 自动处理。
     *
     * @param worker 要归还的 Worker
     */
    void release(Worker worker);

}
