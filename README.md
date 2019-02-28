# emulator

Allows you to emulate an Android ARM32 and/or ARM64 native library.<br>

This is an educational project to learn more about the ELF file format and ARM assembly.


## Usage

Simple tests under src/test directory
- src/test/java/com/bytedance/frameworks/core/encrypt/TTEncrypt.java
- src/test/java/com/sun/jna/JniDispatch32.java
- src/test/java/com/sun/jna/JniDispatch64.java
- src/test/java/org/telegram/messenger/Utilities32.java
- src/test/java/org/telegram/messenger/Utilities64.java

## Features
- Emulation of the JNI Invocation API so JNI_OnLoad can be called.
- Support JavaVM, JNIEnv.
- Emulation of syscalls instruction.
- Support ARM32 and ARM64 bit ELF.
- Inline hook, thanks to HookZz.
- Import hook, thanks to xHook.
- Support simple debugger, trace code, memory read/write.

## Thanks
- [unicorn](https://github.com/unicorn-engine/unicorn)
- [HookZz](https://github.com/jmpews/HookZz)
- [xHook](https://github.com/iqiyi/xHook)
- [AndroidNativeEmu](https://github.com/AeonLucid/AndroidNativeEmu)
- [usercorn](https://github.com/lunixbochs/usercorn)
- [keystone](https://github.com/keystone-engine/keystone)
- [capstone](https://github.com/aquynh/capstone)
- [idaemu](https://github.com/36hours/idaemu)
- [jelf](https://github.com/fornwall/jelf)
