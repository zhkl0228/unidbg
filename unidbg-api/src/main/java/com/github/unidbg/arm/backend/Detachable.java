package com.github.unidbg.arm.backend;

public interface Detachable {

    void onAttach(UnHook unHook);

    void detach();

}
