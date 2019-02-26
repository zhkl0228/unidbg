package cn.banny.emulator.linux;

public class MemRegion implements Comparable<MemRegion> {

    public final long begin;
    public final long end;
    public final int perms;
    public final String name;
    public final long offset;

    MemRegion(long begin, long end, int perms, String name, long offset) {
        this.begin = begin;
        this.end = end;
        this.perms = perms;
        this.name = name;
        this.offset = offset;
    }

    @Override
    public int compareTo(MemRegion o) {
        return (int) (begin - o.begin);
    }
}
