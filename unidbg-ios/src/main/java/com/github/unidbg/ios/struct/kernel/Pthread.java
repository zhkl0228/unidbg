package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;

public abstract class Pthread extends UnidbgStructure {

    public static Pthread create(Emulator<?> emulator, Pointer pointer) {
        Pthread pthread = emulator.is64Bit() ? new Pthread64(pointer) : new Pthread32(pointer);
        pthread.unpack();
        return pthread;
    }

    private static final int MAXTHREADNAMESIZE = 64;
    public static final int PTHREAD_CREATE_JOINABLE = 1;

    public Pthread(Emulator<?> emulator, byte[] data) {
        super(emulator, data);
    }

    public Pthread(Pointer p) {
        super(p);
    }

    public byte[] pthread_name = new byte[MAXTHREADNAMESIZE]; // includes NUL

    public String getName() {
        return new String(pthread_name, StandardCharsets.UTF_8).trim();
    }

    public UnidbgPointer getTSD() {
        return (UnidbgPointer) getPointer().share(fieldOffset("self"));
    }

    public Pointer getErrno() {
        return getPointer().share(fieldOffset("errno"));
    }

    public abstract void setStack(Pointer stackAddress, long stackSize);

    public abstract void setThreadId(int threadId);

    public abstract int getThreadId();

    public abstract void setSig(long sig);

    public abstract void setDetached(int detached);

    public abstract void setExitValue(int value);

    public abstract void setSelf(Pointer self);
    public abstract void setMachThreadSelf(long machThreadSelf);

    public abstract Pointer getErrnoPointer(Emulator<?> emulator);

}
