# unidbg

Allows you to emulate an Android ARM32 and/or ARM64 native library, and an experimental  iOS ARM32 emulation.<br>

This is an educational project to learn more about the ELF file format and ARM assembly.

## License
- unidbg uses software libraries from [Apache Software Foundation](http://apache.org). 
- unidbg developers Idea enterprise licenses are supported by [Jetbrains](https://www.jetbrains.com?from=unidbg).
- [IntelliJ IDEA](https://www.jetbrains.com/idea?from=unidbg) can be used to edit unidbg sources.
- ![](assets/idea_logo.svg)

## Usage

VM options: -Djava.library.path=prebuilt/os -Djna.library.path=prebuilt/os  
Where os may: linux64, win32, win64, osx64

Simple tests under src/test directory
- [src/test/java/com/bytedance/frameworks/core/encrypt/TTEncrypt.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/com/bytedance/frameworks/core/encrypt/TTEncrypt.java)  

![](assets/TTEncrypt.gif)
***
- [src/test/java/com/sun/jna/JniDispatch32.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/com/sun/jna/JniDispatch32.java)  
![](assets/JniDispatch32.gif)
***
- [src/test/java/com/sun/jna/JniDispatch64.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/com/sun/jna/JniDispatch64.java)  
![](assets/JniDispatch64.gif)
***
- [src/test/java/org/telegram/messenger/Utilities32.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/org/telegram/messenger/Utilities32.java)  
![](assets/Utilities32.gif)
***
- [src/test/java/org/telegram/messenger/Utilities64.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/org/telegram/messenger/Utilities64.java)  
![](assets/Utilities64.gif)

## More tests
- [src/test/java/com/github/unidbg/android/QDReaderJni.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/com/github/unidbg/android/QDReaderJni.java)

## Features
- Emulation of the JNI Invocation API so JNI_OnLoad can be called.
- Support JavaVM, JNIEnv.
- Emulation of syscalls instruction.
- Support ARM32 and ARM64 bit ELF.
- Inline hook, thanks to HookZz.
- Import hook, thanks to xHook.
- Support simple debugger, gdb stub, instruction trace, memory read/write trace.

## TODO
- ~~Working iOS emulation.~~
- ~~Add more iOS syscall.~~

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
- [whale](https://github.com/asLody/whale)
- [kaitai_struct](https://github.com/kaitai-io/kaitai_struct)
- [fishhook](https://github.com/facebook/fishhook)
