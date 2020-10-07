package com.github.unidbg.android.ida;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.context.EditableArm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

class MyARM64SyscallHandler extends ARM64SyscallHandler {

    public MyARM64SyscallHandler(SvcMemory svcMemory) {
        super(svcMemory);
    }

    @Override
    protected boolean handleUnknownSyscall(Emulator<?> emulator, int NR) {
        EditableArm64RegisterContext context = emulator.getContext();
        if (NR == 260) {
            int pid = context.getXInt(0);
            Pointer wstatus = context.getXPointer(1);
            int options = context.getXInt(2);
            Pointer rusage = context.getXPointer(3);
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
            String newPath = "/system/bin/android_server64_7.4\0";
            buf.setString(0, newPath);
            System.out.println("readlink: path=" + path + ", newPath=" + newPath);
            return newPath.length();
        }

        System.out.println("readlink: path=" + path);
        return super.readlink(emulator, path, buf, bufSize);
    }

    @Override
    protected long fork(Emulator<?> emulator) {
        return emulator.getPid();
    }

    @Override
    protected long ptrace(Emulator<?> emulator) {
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
                long val = addr.getLong(0);
                data.setLong(0, val);
                break;
            }
            case PTrace.PTRACE_GETREGSET: {
                if (addr.toUIntPeer() == PTrace.NT_PRSTATUS) {
                    Arm64Register register = new Arm64Register(data);
                    register.fill(emulator.getBackend());
                    register.pack();
                    System.out.println(register);
                    break;
                } else {
                    throw new UnsupportedOperationException();
                }
            }
            /*case PTrace.PTRACE_PEEKUSR: {
                int off = (int) addr.toUIntPeer() / 4;
                int reg = ArmConst.UC_ARM_REG_INVALID;
                if (off == Reg32.ARM_pc) {
                    reg = ArmConst.UC_ARM_REG_PC;
                } else {
                    msg += (", off=" + off);
                }
                if (reg != ArmConst.UC_ARM_REG_INVALID) {
                    data.setInt(0, ArmRegister.readReg(u, reg));
                    break;
                }
            }*/
            default:
                System.err.println(msg);
                emulator.attach().debug();
                return -1;
        }
        return 0;
    }
}
