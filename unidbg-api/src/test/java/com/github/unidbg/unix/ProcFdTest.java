package com.github.unidbg.unix;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ProcFdTest {

    @Test
    public void resolvesSelfAndCurrentPidPaths() {
        assertEquals(3, UnixSyscallHandler.parseProcFd("/proc/self/fd/3", 100));
        assertEquals(12, UnixSyscallHandler.parseProcFd("/proc/100/fd/12", 100));
    }

    @Test
    public void ignoresOtherPidAndMalformedPaths() {
        assertEquals(-1, UnixSyscallHandler.parseProcFd("/proc/101/fd/3", 100));
        assertEquals(-1, UnixSyscallHandler.parseProcFd("/proc/self/fd/", 100));
        assertEquals(-1, UnixSyscallHandler.parseProcFd("/proc/self/fd/abc", 100));
        assertEquals(-1, UnixSyscallHandler.parseProcFd("/proc/self/fd/3/sub", 100));
        assertEquals(-1, UnixSyscallHandler.parseProcFd("/data/app/base.apk", 100));
    }
}
