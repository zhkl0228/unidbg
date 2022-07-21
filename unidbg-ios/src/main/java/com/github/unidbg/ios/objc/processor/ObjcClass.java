package com.github.unidbg.ios.objc.processor;

public interface ObjcClass {

    String getName();

    ObjcClass getMeta();

    ObjcMethod[] getMethods();

}
