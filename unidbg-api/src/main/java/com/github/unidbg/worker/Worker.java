package com.github.unidbg.worker;

public abstract class Worker implements AutoCloseable {

    private final WorkerPool pool;

    public Worker(WorkerPool pool) {
        this.pool = pool;
    }

    public abstract void destroy();

    @Override
    public final void close() {
        pool.release(this);
    }

}
