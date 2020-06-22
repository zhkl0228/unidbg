package com.github.unidbg.ios;

class Section {
    final long addr;
    final long size;
    Section(long addr, long size) {
        this.addr = addr;
        this.size = size;
    }
}
