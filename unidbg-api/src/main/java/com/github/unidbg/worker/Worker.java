package com.github.unidbg.worker;

/**
 * 工作单元接口，表示池中可复用的资源（如模拟器实例）。
 *
 * <p>实现类应在 {@link #destroy()} 中释放所持有的底层资源。
 * 借出和归还由 {@link WorkerPool} 和 {@link WorkerLoan} 管理，Worker 本身无需感知池的存在。</p>
 *
 * @see WorkerPool
 * @see WorkerLoan
 */
public interface Worker {

    /**
     * 销毁此 Worker 持有的底层资源。
     * 当 Worker 不再被池管理时（如池关闭），由池调用此方法进行清理。
     */
    void destroy();

}
