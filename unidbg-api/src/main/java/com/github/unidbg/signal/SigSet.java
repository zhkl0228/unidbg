package com.github.unidbg.signal;

public interface SigSet extends Iterable<Integer> {

    long getMask();

    void setMask(long mask);

    void blockSigSet(long mask);

    void unblockSigSet(long mask);

    boolean containsSigNumber(int signum);

    void removeSigNumber(int signum);

    void addSigNumber(int signum);

}
