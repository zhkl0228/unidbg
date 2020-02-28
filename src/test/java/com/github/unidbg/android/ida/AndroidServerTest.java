package com.github.unidbg.android.ida;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.xhook.IxHook;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.XHookImpl;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.DirectoryFileIO;
import com.github.unidbg.linux.file.MapsFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;

public class AndroidServerTest implements IOResolver<AndroidFileIO>, PTrace {

    public static void main(String[] args) throws IOException {
        new AndroidServerTest().test();
    }

    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        final int attachPid = emulator.getPid() - 1;
        if (("/proc/" + attachPid + "/maps").equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new MapsFileIO(oflags, pathname, emulator.getMemory().getLoadedModules()));
        }
        if (("/proc/" + attachPid + "/cmdline").equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, ("/system/bin/" + executable.getName()).getBytes()));
        }
        if (("/proc/" + attachPid + "/task/" + attachPid + "/comm").equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, (executable.getName() + "\n").getBytes()));
        }
        if (("/proc/" + attachPid + "/exe").equals(pathname) || "/system/bin/android_server_7.4".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, executable, pathname));
        }
        if ("/proc".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new DirectoryFileIO(oflags, pathname, new DirectoryFileIO.DirectoryEntry(false, Integer.toString(attachPid))));
        }
        if (("/proc/" + attachPid).equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new DirectoryFileIO(oflags, pathname,
                    new DirectoryFileIO.DirectoryEntry(true, "maps"),
                    new DirectoryFileIO.DirectoryEntry(true, "cmdline"),
                    new DirectoryFileIO.DirectoryEntry(true, "exe"),
                    new DirectoryFileIO.DirectoryEntry(false, "task")));
        }

        return null;
    }

    private final Emulator<AndroidFileIO> emulator;
    private final Module module;
    private final File executable;

    private AndroidServerTest() throws IOException {
        executable = new File("src/test/resources/example_binaries/ida/android_server_7.4");
        emulator = new MyAndroidARMEmulator(executable);
        emulator.getSyscallHandler().addIOResolver(this);
        Memory memory = emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(19);
        memory.setLibraryResolver(resolver);

        memory.setCallInitFunction();

        module = emulator.loadLibrary(executable);
    }

    private void test() {
        IxHook ixHook = XHookImpl.getInstance(emulator);
        ixHook.register(executable.getName(), "ptrace", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                int request = context.getIntArg(0);
                Pointer addr = context.getPointerArg(2);
                Pointer data = context.getPointerArg(3);
                if (request != PTrace.PTRACE_PEEKTEXT && request != PTrace.PTRACE_POKEDATA) {
                    System.err.println("ptrace request=" + request + ", addr=" + addr + ", data=" + data + ", LR=" + context.getLRPointer());
                }
                return super.onCall(emulator, originFunction);
            }
        });
        ixHook.refresh();

        emulator.attach().addBreakPoint(null, 0x4006816C);

        System.err.println("exit code: " + module.callEntry(emulator, "--verbose"));
    }

}
