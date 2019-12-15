package cn.banny.unidbg.file;

import cn.banny.auxiliary.Inspector;

public class DumpFileIO extends AbstractFileIO {

    private final int fd;

    public DumpFileIO(int fd) {
        super(0);

        this.fd = fd;
    }

    @Override
    public int write(byte[] data) {
        Inspector.inspect(data, "Dump for fd: " + fd);
        return data.length;
    }

    @Override
    public void close() {
    }

    @Override
    public FileIO dup2() {
        return this;
    }
}
