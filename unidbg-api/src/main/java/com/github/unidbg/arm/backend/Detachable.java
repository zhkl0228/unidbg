package com.github.unidbg.arm.backend;

import unicorn.Unicorn;

public interface Detachable {

    void onAttach(Unicorn.UnHook unHook);

    void detach();

}
