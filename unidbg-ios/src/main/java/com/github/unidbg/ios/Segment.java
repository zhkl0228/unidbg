package com.github.unidbg.ios;

final class Segment {

    final long virtual_address;
    final long mem_size;
    final long offset;
    final long file_size;

    Segment(long virtual_address, long mem_size, long offset, long file_size) {
        this.virtual_address = virtual_address;
        this.mem_size = mem_size;
        this.offset = offset;
        this.file_size = file_size;
    }

    @Override
    public String toString() {
        return "Segment{" +
                "virtual_address=" + virtual_address +
                ", mem_size=" + mem_size +
                ", offset=" + offset +
                ", file_size=" + file_size +
                '}';
    }

}
