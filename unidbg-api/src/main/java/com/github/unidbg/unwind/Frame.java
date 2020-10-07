package com.github.unidbg.unwind;

import com.github.unidbg.pointer.UnidbgPointer;

public class Frame {

    public final UnidbgPointer ip, fp;

    public Frame(UnidbgPointer ip, UnidbgPointer fp) {
        this.ip = ip;
        this.fp = fp;
    }

    final boolean isFinish() {
        return fp == null;
    }

}
