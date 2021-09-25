package com.github.unidbg.spi;

import com.github.unidbg.Module;

public interface InitFunctionListener {

    void onPreCallInitFunction(Module module, long initFunction, int index);

    void onPostCallInitFunction(Module module, long initFunction, int index);

}
