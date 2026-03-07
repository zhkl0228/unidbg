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
     * 设置空闲超时时间，超过此时间未被借出的 Worker 将被自动销毁。
     * 最低不能低于 1 分钟，默认 10 分钟。
     *
     * @param idleTimeoutMinutes 空闲超时（分钟），最小值为 1
     */
    void setIdleTimeout(int idleTimeoutMinutes);

    /**
     * 设置最小保持的 Worker 数量，空闲清理时不会将存活数量降到此值以下。
     * 不能低于 1，默认为 1。
     *
     * @param minIdle 最小保持数量，最小值为 1
     */
    void setMinIdle(int minIdle);

    /**
     * 设置初始 Worker 数量，管理线程会预先创建指定数量的 Worker 放入池中。
     * 不能超过 maxWorkers，不能低于 0，默认为 0（完全懒创建）。
     *
     * @param initialSize 初始 Worker 数量
     */
    void setInitialSize(int initialSize);

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
