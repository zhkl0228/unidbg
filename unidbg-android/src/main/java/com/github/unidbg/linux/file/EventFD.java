package com.github.unidbg.linux.file;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.file.linux.BaseAndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class EventFD extends BaseAndroidFileIO implements NewFileIO {

    private static final Logger log = LoggerFactory.getLogger(EventFD.class);

    private final boolean semaphore;
    private final boolean nonblock;
    private long counter;

    public EventFD(int initval, boolean semaphore, boolean nonblock) {
        super(IOConstants.O_RDWR);
        this.counter = initval;
        this.semaphore = semaphore;
        this.nonblock = nonblock;
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        if (count != 8) {
            return super.read(backend, buffer, count);
        }
        if (counter == 0) {
            if (nonblock) {
                return -1;
            } else {
                throw new UnsupportedOperationException();
            }
        }
        if (semaphore) {
            buffer.setLong(0, 1);
            counter--;
        } else {
            buffer.setLong(0, counter);
            counter = 0;
        }
        return 8;
    }

    @Override
    public int write(byte[] data) {
        if (data.length != 8) {
            return super.write(data);
        }

        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        long cnt = buffer.getLong();
        counter += cnt;
        log.debug("write cnt={}, counter={}", cnt, counter);
        return 8;
    }

    @Override
    public void close() {
    }

}
