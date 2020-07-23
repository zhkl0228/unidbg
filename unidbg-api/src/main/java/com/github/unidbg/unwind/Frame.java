package com.github.unidbg.unwind;

import com.github.unidbg.pointer.UnicornPointer;

public class Frame {

    public final UnicornPointer ip, fp;

    public Frame(UnicornPointer ip, UnicornPointer fp) {
        this.ip = ip;
        this.fp = fp;
    }

    final boolean isFinish() {
        return fp == null;
    }

}
