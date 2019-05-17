package cn.banny.unidbg.linux.file;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.file.AbstractFileIO;
import cn.banny.unidbg.file.FileIO;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;

public class DriverFileIO extends AbstractFileIO implements FileIO {

    private static final Log log = LogFactory.getLog(DriverFileIO.class);

    public static DriverFileIO create(int oflags, String pathname) {
        if ("/dev/urandom".equals(pathname) || "/dev/random".equals(pathname)) {
            return new RandomFileIO(pathname);
        }
        if ("/dev/alarm".equals(pathname) || "/dev/null".equals(pathname)) {
            return new DriverFileIO(oflags, pathname);
        }
        if ("/dev/ashmem".equals(pathname)) {
            return new Ashmem(oflags, pathname);
        }
        return null;
    }

    private final String path;

    DriverFileIO(int oflags, String path) {
        super(oflags);
        this.path = path;
    }

    @Override
    public void close() {
    }

    @Override
    public int write(byte[] data) {
        throw new AbstractMethodError();
    }

    @Override
    public int read(Unicorn unicorn, Pointer buffer, int count) {
        throw new AbstractMethodError();
    }

    @Override
    public int ioctl(Emulator emulator, long request, long argp) {
        if ("/dev/alarm".equals(path)) {
            if (request == 0x40086134L) { // 未知调用
                return -1;
            }
            log.info("alarm ioctl request=0x" + Long.toHexString(request) + ", argp=0x" + Long.toHexString(argp));
            return 0;
        }

        return super.ioctl(emulator, request, argp);
    }

    @Override
    public FileIO dup2() {
        throw new AbstractMethodError();
    }

    @Override
    public String toString() {
        return path;
    }
}
