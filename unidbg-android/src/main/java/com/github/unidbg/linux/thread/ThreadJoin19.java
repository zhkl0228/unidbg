package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Arrays;

public class ThreadJoin19 {

    private static final Log log = LogFactory.getLog(ThreadJoin19.class);

    public static void patch(Emulator<?> emulator, IHookZz hookZz) {
        if (emulator.is64Bit()) {
            throw new IllegalStateException();
        }
        Memory memory = emulator.getMemory();
        SvcMemory svcMemory = emulator.getSvcMemory();
        Module libc = memory.findModule("libc.so");
        Symbol _pthread_clone = libc.findSymbolByName("__pthread_clone", false);
        if (_pthread_clone == null) {
            throw new IllegalStateException("find __pthread_clone failed.");
        }
        hookZz.replace(_pthread_clone, svcMemory.registerSvc(new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                Arm32RegisterContext context = emulator.getContext();
                Pointer start_routine = context.getPointerArg(0);
                Pointer child_stack = context.getPointerArg(1);
                int flags = context.getIntArg(2);
                Pointer arg = context.getPointerArg(3);
                log.info("pthread_clone start_routine=" + start_routine + ", child_stack=" + child_stack + ", flags=0x" + Integer.toHexString(flags) + ", arg=" + arg);
                return context.getR0Int();
            }
            @Override
            public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                    KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                            "push {r4-r7, lr}",
                            "svc #0x" + Integer.toHexString(svcNumber),
                            "mov ip, r0",
                            "mov r0, r3",
                            "blx ip",
                            "mov r0, #1",
                            "pop {r4-r7, pc}"));
                    byte[] code = encoded.getMachineCode();
                    UnidbgPointer pointer = svcMemory.allocate(code.length, "ArmSvc");
                    pointer.write(code);
                    return pointer;
                }
            }
        }));
    }

}
