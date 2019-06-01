package cn.banny.unidbg.ios.classdump;

import cn.banny.unidbg.hook.IHook;

public interface IClassDumper extends IHook {

    String dumpClass(String className);

}
