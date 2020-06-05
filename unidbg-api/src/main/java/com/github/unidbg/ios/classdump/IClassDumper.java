package com.github.unidbg.ios.classdump;

import com.github.unidbg.hook.IHook;

public interface IClassDumper extends IHook {

    String dumpClass(String className);

    void searchClass(String keywords);

}
