package com.github.unidbg.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.ARMSyscallHandler;
import com.github.unidbg.linux.android.AndroidARMEmulator;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.MapsFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.io.File;
import java.io.IOException;

public class AndroidServerTest implements IOResolver<AndroidFileIO>, PTrace {

    public static void main(String[] args) throws IOException {
        new AndroidServerTest().test();
    }

    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        if ("/proc/1/maps".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new MapsFileIO(oflags, pathname, emulator.getMemory().getLoadedModules()));
        }
        if ("/proc/1/cmdline".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, "android_server_7.4".getBytes()));
        }
        if ("/proc/1/task/1/comm".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, "comm".getBytes()));
        }
        if ("/proc/1/exe".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, new File("src/test/resources/example_binaries/ida/android_server_7.4"), pathname));
        }

        return null;
    }

    private final Emulator<AndroidFileIO> emulator;
    private final Module module;

    private AndroidServerTest() throws IOException {
        File executable = new File("src/test/resources/example_binaries/ida/android_server_7.4");
        emulator = new AndroidARMEmulator(executable.getName(), new File("target/rootfs/ida")) {
            @Override
            protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
                return new ARMSyscallHandler(svcMemory) {
                    @Override
                    protected int fork(Emulator<?> emulator) {
                        return emulator.getPid();
                    }
                    @Override
                    protected boolean handleUnknownSyscall(Emulator<?> emulator, int NR) {
                        EditableArm32RegisterContext context = emulator.getContext();
                        if (NR == 114) {
                            int pid = context.getR0Int();
                            Pointer wstatus = context.getR1Pointer();
                            int options = context.getR2Int();
                            Pointer rusage = context.getR3Pointer();
                            System.out.println("wait4 pid=" + pid + ", wstatus=" + wstatus + ", options=0x" + Integer.toHexString(options) + ", rusage=" + rusage);
                            return true;
                        }
                        return super.handleUnknownSyscall(emulator, NR);
                    }
                    @Override
                    protected int ptrace(Unicorn u, Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        int request = context.getIntArg(0);
                        int pid = context.getIntArg(1);
                        Pointer addr = context.getPointerArg(2);
                        Pointer data = context.getPointerArg(3);
                        int ret = 0;
                        switch (request) {
                            case PTRACE_ATTACH:
                            case PTRACE_CONT:
                                break;
                            case PTRACE_PEEKUSR:
                                ret = 0x88;
                                break;
                            case PTRACE_PEEKTEXT:
                                ret = addr.getInt(0);
                                break;
                        }
                        System.out.println("ptrace request=0x" + Integer.toHexString(request) + ", pid=" + pid + ", addr=" + addr + ", data=" + data + ", ret=0x" + Integer.toHexString(ret));
                        return ret;
                    }
                };
            }
        };
        emulator.getSyscallHandler().addIOResolver(this);
        Memory memory = emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);

        memory.setCallInitFunction();

        module = emulator.loadLibrary(executable);
    }

    private void test() {
        System.err.println("exit code: " + module.callEntry(emulator, "--verbose"));
    }

}
