package com.github.unidbg.linux.file;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.file.linux.BaseAndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.sun.jna.Pointer;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;

public class BidirectionalPipeIO extends BaseAndroidFileIO implements NewFileIO {
    BidirectionalPipeIO target;
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public BidirectionalPipeIO() {
        super(IOConstants.O_RDWR);
    }

    public void setTarget(BidirectionalPipeIO target) {
        this.target = target;
    }

    @Override
    public int write(byte[] data) {
        target.buffer.write(data, 0, data.length);
        return data.length;
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        // read local buffer
        byte[] data = this.buffer.toByteArray();
        int read = Math.min(count, data.length);
        buffer.write(0, data, 0, read);
        this.buffer.reset();
        return read;
    }
}
