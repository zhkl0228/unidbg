package com.github.unidbg.signal;

public interface SigSet {

    long getSigSet();

    void blockSigSet(long value);

    void unblockSigSet(long value);

    boolean containsSigNumber(int signum);

    void removeSigNumber(int signum);

    void addSigNumber(int signum);

}
