package com.github.unidbg.file;

public class FileResult {

    public static FileResult success(FileIO io) {
        if (io == null) {
            throw new NullPointerException("io is null");
        }

        return new FileResult(io, 0);
    }
    public static FileResult failed(int errno) {
        if (errno == 0) {
            throw new IllegalArgumentException("errno=" + errno);
        }

        return new FileResult(null, errno);
    }

    public final FileIO io;
    public final int errno;

    public boolean isSuccess() {
        return io != null && errno == 0;
    }

    private FileResult(FileIO io, int errno) {
        this.io = io;
        this.errno = errno;
    }

}
