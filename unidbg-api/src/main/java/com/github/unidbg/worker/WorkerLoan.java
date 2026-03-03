package com.github.unidbg.worker;

/**
 * Worker 的借出凭证，实现 {@link AutoCloseable} 以支持 try-with-resources 自动归还。
 *
 * <p>通过 {@link #get()} 获取被借出的 Worker 实例，
 * 当 try 块结束时 {@link #close()} 自动将 Worker 归还到池中。</p>
 *
 * <pre>{@code
 * try (WorkerLoan<MyWorker> loan = pool.borrow(1, TimeUnit.MINUTES)) {
 *     if (loan != null) {
 *         MyWorker worker = loan.get();
 *         worker.doWork();
 *     }
 * } // 自动归还
 * }</pre>
 *
 * @param <T> Worker 的具体类型
 * @see WorkerPool#borrow
 */
public class WorkerLoan<T extends Worker> implements AutoCloseable {

    private final T worker;
    private final WorkerPool pool;

    WorkerLoan(T worker, WorkerPool pool) {
        this.worker = worker;
        this.pool = pool;
    }

    /**
     * 获取被借出的 Worker 实例。
     *
     * @return Worker 实例
     */
    public T get() {
        return worker;
    }

    /**
     * 将 Worker 归还到池中。由 try-with-resources 自动调用。
     */
    @Override
    public void close() {
        pool.release(worker);
    }

}
