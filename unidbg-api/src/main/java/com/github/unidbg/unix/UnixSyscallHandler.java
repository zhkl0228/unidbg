package com.github.unidbg.unix;

import com.github.unidbg.Emulator;
import com.github.unidbg.Family;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.debugger.Breaker;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.memory.MemRegion;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.thread.MainTask;
import com.github.unidbg.unix.struct.TimeVal32;
import com.github.unidbg.unix.struct.TimeVal64;
import com.github.unidbg.unix.struct.TimeZone;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataOutput;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class UnixSyscallHandler<T extends NewFileIO> implements SyscallHandler<T> {

    private static final Logger log = LoggerFactory.getLogger(UnixSyscallHandler.class);

    private final List<IOResolver<T>> resolvers = new ArrayList<>(5);

    protected final Map<Integer, T> fdMap = new TreeMap<>();

    @Override
    public FileIO getFileIO(int fd) {
        return fdMap.get(fd);
    }

    @Override
    public void closeFileIO(int fd) {
        FileIO io = fdMap.remove(fd);
        if (io != null) {
            io.close();
        }
    }

    protected boolean verbose;

    @Override
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    private FileListener fileListener;

    public void setFileListener(FileListener fileListener) {
        this.fileListener = fileListener;
    }

    @Override
    public boolean isVerbose() {
        return verbose;
    }

    private Breaker breaker;

    @Override
    public void setBreaker(Breaker breaker) {
        this.breaker = breaker;
    }

    protected final Breaker createBreaker(Emulator<?> emulator) {
        return breaker != null ? breaker : emulator.attach();
    }

    protected int getMinFd() {
        int last_fd = -1;
        for (int fd : fdMap.keySet()) {
            if (last_fd + 1 == fd) {
                last_fd = fd;
            } else {
                break;
            }
        }
        return last_fd + 1;
    }

    @Override
    public int addFileIO(T io) {
        int fd = getMinFd();
        fdMap.put(fd, io);
        return fd;
    }

    @Override
    public void addIOResolver(IOResolver<T> resolver) {
        if (!resolvers.contains(resolver)) {
            resolvers.add(0, resolver);
        }
    }

    protected final FileResult<T> resolve(Emulator<T> emulator, String pathname, int oflags) {
        FileResult<T> failResult = null;
        for (IOResolver<T> resolver : resolvers) {
            FileResult<T> result = resolver.resolve(emulator, pathname, oflags);
            if (result != null && result.isSuccess()) {
                emulator.getMemory().setErrno(0);
                return result;
            } else if (result != null) {
                if (failResult == null || !failResult.isFallback()) {
                    failResult = result;
                }
            }
        }
        if (failResult != null && !failResult.isFallback()) {
            return failResult;
        }

        FileResult<T> result = emulator.getFileSystem().open(pathname, oflags);
        if (result != null && result.isSuccess()) {
            emulator.getMemory().setErrno(0);
            return result;
        } else if (failResult == null) {
            failResult = result;
        }

        Family family = emulator.getFamily();
        if (pathname.endsWith(family.getLibraryExtension())) {
            for (Module module : emulator.getMemory().getLoadedModules()) {
                for (MemRegion memRegion : module.getRegions()) {
                    if (pathname.equals(memRegion.getName())) {
                        try {
                            emulator.getMemory().setErrno(0);
                            return FileResult.success(createByteArrayFileIO(pathname, oflags, memRegion.readLibrary()));
                        } catch (IOException e) {
                            throw new IllegalStateException(e);
                        }
                    }
                }
            }
        }

        if (failResult != null && failResult.isFallback()) {
            return FileResult.success(failResult.io);
        }
        
        if (pathname.startsWith("/proc/" + emulator.getPid() + "/fd/") || pathname.startsWith("/proc/self/fd/")) {
            int fd = Integer.parseInt(pathname.substring(pathname.lastIndexOf("/") + 1));
            T file = fdMap.get(fd);
            if (file != null) {
                return FileResult.success(file);
            }
        }
        if (("/proc/" + emulator.getPid() + "/fd").equals(pathname) || "/proc/self/fd".equals(pathname)) {
            return createFdDir(oflags, pathname);
        }
        if (("/proc/" + emulator.getPid() + "/task/").equals(pathname) || "/proc/self/task/".equals(pathname)) {
            return createTaskDir(emulator, oflags, pathname);
        }
        
        return failResult;
    }

    protected FileResult<T> createTaskDir(Emulator<T> emulator, int oflags, String pathname) {
        throw new UnsupportedOperationException(pathname);
    }

    protected FileResult<T> createFdDir(int oflags, String pathname) {
        throw new UnsupportedOperationException(pathname);
    }

    protected abstract T createByteArrayFileIO(String pathname, int oflags, byte[] data);

    protected long currentTimeMillis() {
        return System.currentTimeMillis();
    }

    @SuppressWarnings("unused")
    protected int gettimeofday(Emulator<?> emulator, Pointer tv, Pointer tz) {
        if (log.isDebugEnabled()) {
            log.debug("gettimeofday tv={}, tz={}", tv, tz);
        }

        if (log.isDebugEnabled()) {
            byte[] before = tv.getByteArray(0, 8);
            Inspector.inspect(before, "gettimeofday tv=" + tv);
        }
        if (tz != null && log.isDebugEnabled()) {
            byte[] before = tz.getByteArray(0, 8);
            Inspector.inspect(before, "gettimeofday tz");
        }

        long currentTimeMillis = currentTimeMillis();
        long tv_sec = currentTimeMillis / 1000;
        long tv_usec = (currentTimeMillis % 1000) * 1000;
        TimeVal32 timeVal = new TimeVal32(tv);
        timeVal.tv_sec = (int) tv_sec;
        timeVal.tv_usec = (int) tv_usec;
        timeVal.pack();

        if (tz != null) {
            Calendar calendar = Calendar.getInstance();
            int tz_minuteswest = -(calendar.get(Calendar.ZONE_OFFSET) + calendar.get(Calendar.DST_OFFSET)) / (60 * 1000);
            TimeZone timeZone = new TimeZone(tz);
            timeZone.tz_minuteswest = tz_minuteswest;
            timeZone.tz_dsttime = 0;
            timeZone.pack();
        }

        if (log.isDebugEnabled()) {
            byte[] after = tv.getByteArray(0, 8);
            Inspector.inspect(after, "gettimeofday tv after tv_sec=" + tv_sec + ", tv_usec=" + tv_usec + ", tv=" + tv);
        }
        if (tz != null && log.isDebugEnabled()) {
            byte[] after = tz.getByteArray(0, 8);
            Inspector.inspect(after, "gettimeofday tz after");
        }
        return 0;
    }

    protected int gettimeofday64(Pointer tv, Pointer tz) {
        if (log.isDebugEnabled()) {
            log.debug("gettimeofday64 tv={}, tz={}", tv, tz);
        }

        if (log.isDebugEnabled()) {
            byte[] before = tv.getByteArray(0, 8);
            Inspector.inspect(before, "gettimeofday tv=" + tv);
        }
        if (tz != null && log.isDebugEnabled()) {
            byte[] before = tz.getByteArray(0, 8);
            Inspector.inspect(before, "gettimeofday tz");
        }

        long currentTimeMillis = currentTimeMillis();
        long tv_sec = currentTimeMillis / 1000;
        long tv_usec = (currentTimeMillis % 1000) * 1000;
        TimeVal64 timeVal = new TimeVal64(tv);
        timeVal.tv_sec = tv_sec;
        timeVal.tv_usec = tv_usec;
        timeVal.pack();

        if (tz != null) {
            Calendar calendar = Calendar.getInstance();
            int tz_minuteswest = -(calendar.get(Calendar.ZONE_OFFSET) + calendar.get(Calendar.DST_OFFSET)) / (60 * 1000);
            TimeZone timeZone = new TimeZone(tz);
            timeZone.tz_minuteswest = tz_minuteswest;
            timeZone.tz_dsttime = 0;
            timeZone.pack();
        }

        if (log.isDebugEnabled()) {
            byte[] after = tv.getByteArray(0, 8);
            Inspector.inspect(after, "gettimeofday tv after tv_sec=" + tv_sec + ", tv_usec=" + tv_usec + ", tv=" + tv);
        }
        if (tz != null && log.isDebugEnabled()) {
            byte[] after = tz.getByteArray(0, 8);
            Inspector.inspect(after, "gettimeofday tz after");
        }
        return 0;
    }

    protected int sigprocmask(Emulator<?> emulator, int how, Pointer set, Pointer oldset) {
        if (log.isDebugEnabled()) {
            log.debug("sigprocmask how={}, set={}, oldset={}", how, set, oldset);
        }
        emulator.getMemory().setErrno(UnixEmulator.EINVAL);
        return -1;
    }

    protected final int read(Emulator<?> emulator, int fd, Pointer buffer, int count) {
        if (log.isDebugEnabled()) {
            log.debug("read fd={}, buffer={}, count={}, from={}", fd, buffer, count, emulator.getContext().getLRPointer());
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int read = file.read(emulator.getBackend(), buffer, count);
        if (verbose && !file.isStdIO()) {
            System.out.printf("Read %d bytes from '%s'%n", read, file);
        }
        if (fileListener != null) {
            byte[] bytes;
            if (read <= 0) {
                bytes = new byte[0];
            } else {
                bytes = buffer.getByteArray(0, read);
            }
            fileListener.onRead(emulator, String.valueOf(file), bytes);
        }
        return read;
    }

    protected final int pread(Emulator<?> emulator, int fd, Pointer buffer, int count, long offset) {
        if (log.isDebugEnabled()) {
            log.debug("pread fd={}, buffer={}, count={}, offset={}, from={}", fd, buffer, count, offset, emulator.getContext().getLRPointer());
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int read = file.pread(emulator.getBackend(), buffer, count, offset);
        if (verbose) {
            System.out.printf("PRead %d bytes with offset %d from '%s'%n", read, offset, file);
        }
        return read;
    }

    protected final int close(Emulator<?> emulator, int fd) {
        FileIO file = fdMap.remove(fd);
        if (file != null) {
            file.close();
            if (verbose) {
                System.out.printf("File closed '%s' from %s%n", file, emulator.getContext().getLRPointer());
            }
            if (fileListener != null) {
                fileListener.onClose(emulator, file);
            }
            return 0;
        } else {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
    }

    @Override
    public final int open(Emulator<T> emulator, String pathname, int oflags) {
        int minFd = this.getMinFd();

        FileResult<T> resolveResult = resolve(emulator, pathname, oflags);
        if (resolveResult != null && resolveResult.isSuccess()) {
            emulator.getMemory().setErrno(0);
            this.fdMap.put(minFd, resolveResult.io);
            if (verbose) {
                System.out.printf("File opened '%s' with oflags=0x%x from %s%n", resolveResult.io, oflags, emulator.getContext().getLRPointer());
            }
            if (fileListener != null) {
                fileListener.onOpenSuccess(emulator, pathname, resolveResult.io);
            }
            return minFd;
        }

        T driverIO = createDriverFileIO(emulator, oflags, pathname);
        if (driverIO != null) {
            emulator.getMemory().setErrno(0);
            this.fdMap.put(minFd, driverIO);
            if (verbose) {
                System.out.printf("File opened '%s' with oflags=0x%x from %s%n", driverIO, oflags, emulator.getContext().getLRPointer());
            }
            if (fileListener != null) {
                fileListener.onOpenSuccess(emulator, pathname, driverIO);
            }
            return minFd;
        }

        FileResult<T> result = null;
        if (resolveResult != null) {
            result = resolveResult;
        }
        int errno = result != null ? result.errno : UnixEmulator.ENOENT;
        emulator.getMemory().setErrno(errno);
        if (verbose) {
            System.out.printf("File opened '%s' with oflags=0x%x errno is %d from %s%n", pathname, oflags, errno, emulator.getContext().getLRPointer());
        }
        return -1;
    }

    protected abstract T createDriverFileIO(Emulator<?> emulator, int oflags, String pathname);

    protected int fcntl(Emulator<?> emulator, int fd, int cmd, long arg) {
        if (log.isDebugEnabled()) {
            log.debug("fcntl fd={}, cmd={}, arg={}", fd, cmd, arg);
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.fcntl(emulator, cmd, arg);
    }

    private static final Pattern FD_PATTERN = Pattern.compile("/proc/self/fd/(\\d+)");

    protected int readlink(Emulator<?> emulator, String path, Pointer buf, int bufSize) {
        if (log.isDebugEnabled()) {
            log.debug("readlink path={}, buf={}, bufSize={}", path, buf, bufSize);
        }
        Matcher matcher = FD_PATTERN.matcher(path);
        if (matcher.find()) {
            int fd = Integer.parseInt(matcher.group(1));
            FileIO io = fdMap.get(fd);
            if (io != null) {
                path = io.getPath();
            }
        }
        buf.setString(0, path);
        return path.length() + 1;
    }

    private final Map<Integer, byte[]> sigMap = new HashMap<>();

    private static final int SIGHUP = 1;
    private static final int SIGINT = 2;
    private static final int SIGQUIT = 3;
    private static final int SIGILL = 4;
    private static final int SIGTRAP = 5; /* Trace trap (POSIX).  */
    private static final int SIGABRT = 6;
    protected static final int SIGBUS = 7; /* BUS error (4.2 BSD).  */
    private static final int SIGFPE = 8; /* Floating-point exception (ANSI).  */
    private static final int SIGUSR1 = 10;
    private static final int SIGSEGV = 11;
    private static final int SIGUSR2 = 12;
    private static final int SIGPIPE = 13;
    private static final int SIGALRM = 14;
    private static final int SIGTERM = 15;
    protected static final int SIGCHLD = 17;
    private static final int SIGCONT = 18;
    private static final int SIGTSTP = 20;
    private static final int SIGTTIN = 21;
    private static final int SIGTTOU = 22;
    private static final int SIGWINCH = 28;
    private static final int SIGSYS = 31; /* Bad system call.  */
    private static final int SIGRTMIN = 32;

    protected int sigaction(Emulator<?> emulator, int signum, Pointer act, Pointer oldact) {
        final int ACT_SIZE = 16;
        return sigaction(emulator, signum, act, oldact, ACT_SIZE);
    }

    protected final int sigaction(Emulator<?> emulator, int signum, Pointer act, Pointer oldact, int sizeOfSigAction) {
        String prefix = "Unknown";
        if (signum > 32) {
            signum -= 32;
            prefix = "Real-time";
        }
        if (log.isDebugEnabled()) {
            log.debug("sigaction signum={}, act={}, oldact={}, prefix={}", signum, act, oldact, prefix);
        }

        if (oldact != null) {
            byte[] lastAct = sigMap.get(signum);
            byte[] data = lastAct == null ? new byte[sizeOfSigAction] : lastAct;
            oldact.write(0, data, 0, data.length);
        }

        switch (signum) {
            case SIGHUP:
            case SIGINT:
            case SIGQUIT:
            case SIGILL:
            case SIGTRAP:
            case SIGABRT:
            case SIGBUS:
            case SIGFPE:
            case SIGUSR1:
            case SIGSEGV:
            case SIGUSR2:
            case SIGPIPE:
            case SIGALRM:
            case SIGTERM:
            case SIGCHLD:
            case SIGCONT:
            case SIGTSTP:
            case SIGTTIN:
            case SIGTTOU:
            case SIGWINCH:
            case SIGSYS:
            case SIGRTMIN:
                if (act != null) {
                    sigMap.put(signum, act.getByteArray(0, sizeOfSigAction));
                }
                return 0;
        }

        createBreaker(emulator).debug();
        throw new UnsupportedOperationException("signum=" + signum);
    }

    protected final int bind(Emulator<?> emulator, int sockfd, Pointer addr, int addrlen) {
        if (log.isDebugEnabled()) {
            byte[] data = addr.getByteArray(0, addrlen);
            Inspector.inspect(data, "bind sockfd=" + sockfd + ", addr=" + addr + ", addrlen=" + addrlen);
        }

        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.bind(addr, addrlen);
    }

    protected final int listen(Emulator<?> emulator, int sockfd, int backlog) {
        if (log.isDebugEnabled()) {
            log.debug("listen sockfd={}, backlog={}", sockfd, backlog);
        }

        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.listen(backlog);
    }

    protected final int connect(Emulator<?> emulator, int sockfd, Pointer addr, int addrlen) {
        if (log.isDebugEnabled()) {
            byte[] data = addr.getByteArray(0, addrlen);
            Inspector.inspect(data, "connect sockfd=" + sockfd + ", addr=" + addr + ", addrlen=" + addrlen);
        }

        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.connect(addr, addrlen);
    }

    protected final int sendto(Emulator<?> emulator, int sockfd, Pointer buf, int len, int flags, Pointer dest_addr, int addrlen) {
        byte[] data = buf.getByteArray(0, len);
        if (log.isDebugEnabled()) {
            Inspector.inspect(data, "sendto sockfd=" + sockfd + ", buf=" + buf + ", flags=" + flags + ", dest_addr=" + dest_addr + ", addrlen=" + addrlen);
        }
        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.sendto(data, flags, dest_addr, addrlen);
    }

    protected final int write(Emulator<?> emulator, int fd, Pointer buffer, int count) {
        byte[] data = buffer.getByteArray(0, count);
        if (log.isDebugEnabled()) {
            Inspector.inspect(data, "write fd=" + fd + ", buffer=" + buffer + ", count=" + count);
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int write = file.write(data);
        if (verbose && !file.isStdIO()) {
            System.out.printf("Write %d bytes to '%s'%n", write, file);
        }
        if (fileListener != null) {
            byte[] bytes;
            if (write <= 0) {
                bytes = new byte[0];
            } else {
                bytes = Arrays.copyOf(data, write);
            }
            fileListener.onWrite(emulator, String.valueOf(file), bytes);
        }
        return write;
    }

    protected int getrandom(Pointer buf, int bufSize, int flags) {
        Random random = new Random();
        byte[] bytes = new byte[bufSize];
        random.nextBytes(bytes);
        buf.write(0, bytes, 0, bytes.length);
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(bytes, "getrandom buf=" + buf + ", bufSize=" + bufSize + ", flags=0x" + Integer.toHexString(flags)));
        }
        return bufSize;
    }

    @SuppressWarnings("unused")
    protected boolean handleSyscall(Emulator<?> emulator, int NR) {
        return false;
    }

    /**
     * handle unknown syscall
     * @param NR syscall number
     */
    protected boolean handleUnknownSyscall(Emulator<?> emulator, int NR) {
        return false;
    }

    @Override
    public void serialize(DataOutput out) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void onAttach(UnHook unHook) {
    }

    @Override
    public void detach() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void destroy() {
        for (FileIO io : fdMap.values()) {
            io.close();
        }
    }

    protected boolean threadDispatcherEnabled;

    @Override
    public void setEnableThreadDispatcher(boolean threadDispatcherEnabled) {
        this.threadDispatcherEnabled = threadDispatcherEnabled;
    }

    @Override
    public MainTask createSignalHandlerTask(Emulator<?> emulator, int sig) {
        return null;
    }
}
