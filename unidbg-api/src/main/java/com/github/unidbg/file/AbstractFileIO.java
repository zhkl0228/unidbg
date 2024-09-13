package com.github.unidbg.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public abstract class AbstractFileIO implements NewFileIO {

    private static final Logger log = LoggerFactory.getLogger(AbstractFileIO.class);

    private static final int F_GETFD = 1; /* get file descriptor flags */
    private static final int F_SETFD = 2; /* set file descriptor flags */
    private static final int F_GETFL = 3; /* get file status flags */
    private static final int F_SETFL = 4; /* set file status flags */
    private static final int F_SETLK = 6; /* Set record locking info (non-blocking).  */
    private static final int F_SETLKW = 7; /* Set record locking info (blocking).	*/
    private static final int F_ADDFILESIGS = 61; /* add signature from same file (used by dyld for shared libs) */

    private static final int FD_CLOEXEC = 1;

    protected int op;
    protected int oflags;

    protected AbstractFileIO(int oflags) {
        this.oflags = oflags;
    }

    protected abstract void setFlags(long arg);

    @Override
    public int fcntl(Emulator<?> emulator, int cmd, long arg) {
        switch (cmd) {
            case F_GETFD:
                return op;
            case F_SETFD:
                if (FD_CLOEXEC == arg) {
                    op |= FD_CLOEXEC;
                    return 0;
                }
                break;
            case F_GETFL:
                return oflags;
            case F_SETFL:
                setFlags(arg);
                return 0;
            case F_SETLK:
            case F_SETLKW:
            case F_ADDFILESIGS:
                return 0;
        }
        throw new UnsupportedOperationException(getClass().getName() + ", cmd=" + cmd + ", arg=0x" + Long.toHexString(arg & 0xffffffffL) + ", this=" + this);
    }

    @Override
    public int ioctl(Emulator<?> emulator, long request, long argp) {
        if (log.isTraceEnabled()) {
            emulator.attach().debug();
        }
        throw new AbstractMethodError(getClass().getName() + ": request=0x" + Long.toHexString(request) + ", argp=0x" + Long.toHexString(argp));
    }

    @Override
    public int bind(Pointer addr, int addrlen) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int listen(int backlog) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int connect(Pointer addr, int addrlen) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int setsockopt(int level, int optname, Pointer optval, int optlen) {
        throw new AbstractMethodError();
    }

    @Override
    public int getsockopt(int level, int optname, Pointer optval, Pointer optlen) {
        throw new AbstractMethodError(getClass().getName() + ": level=" + level + ", optname=" + optname + ", optval=" + optval + ", optlen=" + optlen);
    }

    @Override
    public int getsockname(Pointer addr, Pointer addrlen) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int sendto(byte[] data, int flags, Pointer dest_addr, int addrlen) {
        throw new AbstractMethodError(Inspector.inspectString(data, "sendto flags=0x" + Integer.toHexString(flags) + ", dest_addr=" + dest_addr + ", addrlen=" + addrlen));
    }

    @Override
    public int recvfrom(Backend backend, Pointer buf, int len, int flags, Pointer src_addr, Pointer addrlen) {
        throw new AbstractMethodError(getClass().getName() + ": recvfrom buf=" + buf + ", len=" + len + ", flags=0x" + Integer.toHexString(flags) + ", src_addr=" + src_addr + ", addrlen=" + addrlen);
    }

    @Override
    public int lseek(int offset, int whence) {
        throw new AbstractMethodError("class=" + getClass() + ", offset=0x" + Long.toHexString(offset) + ", whence=" + whence + ", path=" + getPath());
    }

    @Override
    public int ftruncate(int length) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int getpeername(Pointer addr, Pointer addrlen) {
        throw new AbstractMethodError();
    }

    @Override
    public int shutdown(int how) {
        throw new AbstractMethodError();
    }

    @Override
    public final long mmap2(Emulator<?> emulator, long addr, int aligned, int prot, int offset, int length) throws IOException {
        Backend backend = emulator.getBackend();
        byte[] data = getMmapData(addr, offset, length);
        backend.mem_map(addr, aligned, prot);
        emulator.getMemory().pointer(addr).write(data);
        return addr;
    }

    protected byte[] getMmapData(long addr, int offset, int length) throws IOException {
        throw new AbstractMethodError(getClass().getName() + ", addr=0x" + Long.toHexString(addr) + ", offset=" + offset + ", length=" + length);
    }

    @Override
    public int llseek(long offset, Pointer result, int whence) {
        throw new AbstractMethodError();
    }

    @Override
    public void close() {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int write(byte[] data) {
        throw new UnsupportedOperationException(Inspector.inspectString(data, getClass().getName()));
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int pread(Backend backend, Pointer buffer, int count, long offset) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public FileIO dup2() {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public String getPath() {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public boolean canRead() {
        return true;
    }

    protected boolean stdio;

    @Override
    public boolean isStdIO() {
        return stdio;
    }

}
