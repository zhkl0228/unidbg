package com.github.unidbg.worker;

import java.io.Closeable;
import java.util.concurrent.TimeUnit;

public interface WorkerPool extends Closeable {

    <T extends Worker> T borrow(long timeout, TimeUnit unit);

    void release(Worker worker);

}
