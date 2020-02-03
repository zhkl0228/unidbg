package com.github.unidbg.ios;

import java.nio.ByteBuffer;

class Relocation {

    static Relocation create(ByteBuffer buffer) {
        return new Relocation(buffer.getInt(), buffer.getInt());
    }

    final int address;
    final boolean scattered;
    final int symbolNum;
    final boolean pcRel;
    final int length;
    final boolean extern;
    final int type;

    private Relocation(int address, int value) {
        this.address = address;

        int r_scattered = (address >> 31) & 1;
        this.scattered = r_scattered == 1;

        this.symbolNum = value & 0xffffff;

        int r_pcrel = (value >> 24) & 1;
        this.pcRel = r_pcrel == 1;

        this.length = (value >> 25) & 3;

        int r_extern = (value >> 27) & 1;
        this.extern = r_extern == 1;

        this.type = value >> 28;
    }

}
