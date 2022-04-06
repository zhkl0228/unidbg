package com.bytedance.frameworks.core.encrypt;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.worker.Worker;
import com.github.unidbg.worker.WorkerFactory;
import com.github.unidbg.worker.WorkerPool;
import com.github.unidbg.worker.WorkerPoolFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class TTEncryptWorker extends Worker {

    public static void main(String[] args) throws InterruptedException {
        final WorkerPool pool = WorkerPoolFactory.create(new WorkerFactory() {
            @Override
            public Worker createWorker(WorkerPool pool) {
                return new TTEncryptWorker(pool);
            }
        }, Runtime.getRuntime().availableProcessors());

        int testThreads = 500;
        ExecutorService executorService = Executors.newFixedThreadPool(testThreads);
        for (int i = 0; i < testThreads; i++) {
            final String name = "T" + i;
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    long start = System.currentTimeMillis();
                    try (TTEncryptWorker worker = pool.borrow(1, TimeUnit.MINUTES)) {
                        if (worker != null) {
                            long currentTimeMillis = System.currentTimeMillis();
                            byte[] data = worker.doWork();
                            Inspector.inspect(data, name + ": " + (System.currentTimeMillis() - start) + "ms" + ", " + (System.currentTimeMillis() - currentTimeMillis) + "ms");
                        } else {
                            System.err.println("Borrow failed");
                        }
                    }
                }
            });
        }
        executorService.shutdown();
        if (!executorService.awaitTermination(10, TimeUnit.MINUTES)) {
            throw new IllegalStateException();
        }
        IOUtils.close(pool);
    }

    private final TTEncrypt ttEncrypt;

    public TTEncryptWorker(WorkerPool pool) {
        super(pool);

        ttEncrypt = new TTEncrypt(false);
        System.err.println("Create: " + ttEncrypt);
    }

    @Override
    public void destroy() {
        ttEncrypt.destroy();
        System.err.println("Destroy: " + ttEncrypt);
    }

    private byte[] doWork() {
        return ttEncrypt.ttEncrypt();
    }

}
