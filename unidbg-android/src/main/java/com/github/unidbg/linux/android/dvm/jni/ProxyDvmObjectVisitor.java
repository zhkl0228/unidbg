package com.github.unidbg.linux.android.dvm.jni;

import java.lang.reflect.Member;

public interface ProxyDvmObjectVisitor {

    void onProxyVisit(Member member, Object obj, Object[] args);

    @SuppressWarnings("unused")
    default <T> T postProxyVisit(Member member, Object obj, Object[] args, T result) {
        return result;
    }

}
