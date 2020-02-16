package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;

public abstract class Pthread extends UnicornStructure {

    public static Pthread create(Emulator emulator, Pointer pointer) {
        Pthread pthread = emulator.is64Bit() ? new Pthread64(pointer) : new Pthread32(pointer);
        pthread.unpack();
        return pthread;
    }

    private static final int MAXTHREADNAMESIZE = 64;

    public Pthread(Pointer p) {
        super(p);
    }

    public byte[] pthread_name = new byte[MAXTHREADNAMESIZE]; // includes NUL

    // thread specific data
    public Pointer self;
    public Pointer errno;
    public Pointer mig_reply;

    public String getName() {
        return new String(pthread_name, StandardCharsets.UTF_8).trim();
    }

    public UnicornPointer getTSD() {
        return (UnicornPointer) getPointer().share(fieldOffset("self"));
    }

    public Pointer getErrno() {
        return getPointer().share(fieldOffset("errno"));
    }

}
