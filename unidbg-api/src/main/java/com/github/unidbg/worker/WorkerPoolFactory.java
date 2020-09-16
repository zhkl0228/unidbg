package com.github.unidbg.worker;

public class WorkerPoolFactory {

    public static WorkerPool create(WorkerFactory factory, int workerCount) {
        return new DefaultWorkerPool(factory, workerCount);
    }

}
