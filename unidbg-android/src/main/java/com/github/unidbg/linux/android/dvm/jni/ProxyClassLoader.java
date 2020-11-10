package com.github.unidbg.linux.android.dvm.jni;

class ProxyClassLoader {

    private final ClassLoader classLoader;

    ProxyClassLoader(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    private ProxyClassMapper classNameMapper;

    final void setClassNameMapper(ProxyClassMapper classNameMapper) {
        this.classNameMapper = classNameMapper;
    }

    final Class<?> loadClass(String name) throws ClassNotFoundException {
        Class<?> newClass = classNameMapper == null ? null : classNameMapper.map(name);
        if (newClass != null) {
            return newClass;
        }
        return classLoader.loadClass(name);
    }

}
