package com.github.unidbg.linux.signal;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class SigSet implements com.github.unidbg.signal.SigSet {

    private long value;

    public SigSet(long value) {
        this.value = value;
    }

    @Override
    public long getSigSet() {
        return value;
    }

    @Override
    public void setSigSet(long value) {
        this.value = value;
    }

    @Override
    public void blockSigSet(long value) {
        this.value |= value;
    }

    @Override
    public void unblockSigSet(long value) {
        this.value &= ~value;
    }

    @Override
    public boolean containsSigNumber(int signum) {
        int bit = signum - 1;
        return (value & (1L << bit)) != 0;
    }

    @Override
    public void removeSigNumber(int signum) {
        int bit = signum - 1;
        this.value &= (1L << bit);
    }

    @Override
    public void addSigNumber(int signum) {
        int bit = signum - 1;
        this.value |= (1L << bit);
    }

    private class SigSetIterator implements Iterator<Integer> {

        public SigSetIterator(SigSet sigSet) {
            this.value = sigSet.value;
        }

        private long value;
        private int bit;
        private int nextBit;

        @Override
        public boolean hasNext() {
            for (int i = bit; i < 64; i++) {
                if ((value & (1L << i)) != 0) {
                    nextBit = i;
                    return true;
                }
            }
            return false;
        }
        @Override
        public Integer next() {
            bit = nextBit;
            this.value &= ~(1L << bit);
            return bit + 1;
        }
        @Override
        public void remove() {
            SigSet.this.value &= ~(1L << bit);
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
