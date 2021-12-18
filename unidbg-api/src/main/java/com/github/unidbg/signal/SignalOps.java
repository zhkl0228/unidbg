package com.github.unidbg.signal;

public interface SignalOps {

    SigSet getSigMaskSet();
    void setSigMaskSet(SigSet sigMaskSet);

    SigSet getSigPendingSet();
    void setSigPendingSet(SigSet sigPendingSet);

}
