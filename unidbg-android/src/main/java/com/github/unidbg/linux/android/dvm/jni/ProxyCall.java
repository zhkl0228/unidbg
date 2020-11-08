package com.github.unidbg.linux.android.dvm.jni;

import java.lang.reflect.InvocationTargetException;

interface ProxyCall {

    Object call(Object obj) throws IllegalAccessException, InvocationTargetException, InstantiationException;

}
