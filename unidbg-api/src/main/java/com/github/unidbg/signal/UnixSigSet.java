package com.github.unidbg.signal;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class UnixSigSet implements SigSet {

    private long mask;

    public UnixSigSet(long mask) {
        this.mask = mask;
    }

    @Override
    public long getMask() {
        return mask;
    }

    @Override
    public void setMask(long mask) {
        this.mask = mask;
    }

    @Override
    public void blockSigSet(long mask) {
        this.mask |= mask;
    }

    @Override
    public void unblockSigSet(long mask) {
        this.mask &= ~mask;
    }

    @Override
    public boolean containsSigNumber(int signum) {
        int bit = signum - 1;
        return (mask & (1L << bit)) != 0;
    }

    @Override
    public void removeSigNumber(int signum) {
        int bit = signum - 1;
        this.mask &= (1L << bit);
    }

    @Override
    public void addSigNumber(int signum) {
        int bit = signum - 1;
        this.mask |= (1L << bit);
    }

    private class SigSetIterator implements Iterator<Integer> {

        public SigSetIterator(UnixSigSet sigSet) {
            this.mask = sigSet.mask;
        }

        private long mask;
        private int bit;
        private int nextBit;

        @Override
        public boolean hasNext() {
            for (int i = bit; i < 64; i++) {
                if ((mask & (1L << i)) != 0) {
                    nextBit = i;
                    return true;
                }
            }
            return false;
        }
        @Override
        public Integer next() {
            bit = nextBit;
            this.mask &= ~(1L << bit);
            return bit + 1;
        }
        @Override
        public void remove() {
            UnixSigSet.this.mask &= ~(1L << bit);
        }
    }

    @Override
    public Iterator<Integer> iterator() {
        return new SigSetIterator(this);
    }

    @Override
    public String toString() {
        List<Integer> list = new ArrayList<>(10);
        for (Integer signum : this) {
            list.add(signum);
        }
        return list.toString();
    }

}
