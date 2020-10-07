package com.github.unidbg.android.ida;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.ARM32SyscallHandler;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import unicorn.ArmConst;

class MyARMSyscallHandler extends ARM32SyscallHandler {

    public MyARMSyscallHandler(SvcMemory svcMemory) {
        super(svcMemory);
    }

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
    protected int readlink(Emulator<?> emulator, String path, Pointer buf, int bufSize) {
        int pid = emulator.getPid();
        int attachPid = pid - 1;
        if (("/proc/" + pid + "/exe").equals(path) || ("/proc/" + attachPid + "/exe").equals(path)) {
            String newPath = "/system/bin/android_server_7.4\n";
            buf.setString(0, newPath);
            System.out.println("readlink: path=" + path + ", newPath=" + newPath);
            return newPath.length();
        }

        System.out.println("readlink: path=" + path);
        return super.readlink(emulator, path, buf, bufSize);
    }

    @Override
    protected int ptrace(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        RegisterContext context = emulator.getContext();
        int request = context.getIntArg(0);
        int pid = context.getIntArg(1);
        UnidbgPointer addr = context.getPointerArg(2);
        Pointer data = context.getPointerArg(3);
        String msg = "ptrace request=0x" + Integer.toHexString(request) + ", pid=" + pid + ", addr=" + addr + ", data=" + data + ", LR=" + context.getLRPointer();
        switch (request) {
            case PTrace.PTRACE_ATTACH:
            case PTrace.PTRACE_CONT:
            case PTrace.PTRACE_DETACH:
            case PTrace.PTRACE_KILL:
            case PTrace.PTRACE_POKETEXT:
                break;
            case PTrace.PTRACE_POKEDATA: {
                addr.setPointer(0, data);
                break;
            }
            case PTrace.PTRACE_PEEKTEXT: {
                int val = addr.getInt(0);
                data.setInt(0, val);
                break;
            }
            case PTrace.PTRACE_GETREGS: {
                ArmRegister register = new ArmRegister(data);
                register.fill(backend);
                register.pack();
                System.out.println(register);
                break;
            }
            case PTrace.PTRACE_PEEKUSR: {
                int off = (int) addr.toUIntPeer() / 4;
                int reg = ArmConst.UC_ARM_REG_INVALID;
                if (off == Reg32.ARM_pc) {
                    reg = ArmConst.UC_ARM_REG_PC;
                } else {
                    msg += (", off=" + off);
                }
                if (reg != ArmConst.UC_ARM_REG_INVALID) {
                    data.setInt(0, ArmRegister.readReg(backend, reg));
                    break;
                }
            }
            default:
                System.err.println(msg);
                emulator.attach().debug();
                return -1;
        }
//        System.out.println(msg);
        return 0;
    }

}
