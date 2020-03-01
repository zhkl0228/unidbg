package com.github.unidbg.file;

public class FileResult<T extends NewFileIO> {

    private static final int FALLBACK_ERRNO = -1;

    public static <T extends NewFileIO> FileResult<T> success(T io) {
        if (io == null) {
            throw new NullPointerException("io is null");
        }

        return new FileResult<>(io, 0);
    }
    public static <T extends NewFileIO> FileResult<T> failed(int errno) {
        if (errno == 0) {
            throw new IllegalArgumentException("errno=" + errno);
        }

        return new FileResult<>(null, errno);
    }
    public static <T extends NewFileIO> FileResult<T> fallback(T io) {
        if (io == null) {
            throw new NullPointerException("io is null");
        }

        return new FileResult<>(io, FALLBACK_ERRNO);
    }

    public final T io;
    public final int errno;

    public boolean isSuccess() {
        return io != null && errno == 0;
    }

    public boolean isFallback() {
        return io != null && errno == FALLBACK_ERRNO;
    }

    private FileResult(T io, int errno) {
        this.io = io;
        this.errno = errno;
    }

}
