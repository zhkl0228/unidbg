package com.github.unidbg.ios;

final class Segment {

    final long vmAddr;
    final long vmSize;
    final long fileOffset;
    final long fileSize;

    Segment(long vmAddr, long vmSize, long fileOffset, long fileSize) {
        this.vmAddr = vmAddr;
        this.vmSize = vmSize;
        this.fileOffset = fileOffset;
        this.fileSize = fileSize;
    }

    @Override
    public String toString() {
        return "Segment{" +
                "vmAddr=0x" + Long.toHexString(vmAddr) +
                ", vmSize=0x" + Long.toHexString(vmSize) +
                ", offset=" + fileOffset +
                ", fileSize=0x" + Long.toHexString(fileSize) +
                '}';
    }

}
