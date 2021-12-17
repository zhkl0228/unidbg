package com.github.unidbg.linux.signal;

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
}
