# unidbg

Allows you to emulate an Android ARM32 and/or ARM64 native library, and an experimental  iOS ARM32 emulation.<br>

This is an educational project to learn more about the ELF file format and ARM assembly.

QQ Group: 675443841

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
- [src/test/java/cn/banny/emulator/QDReaderJni.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/cn/banny/emulator/QDReaderJni.java)
- [src/test/java/com/kuaishou/KuaiShouSign.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/com/kuaishou/KuaiShouSign.java) 快手
- [src/test/java/com/meituan/android/common/candy/CandyJni.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/com/meituan/android/common/candy/CandyJni.java) 美团
- [src/test/java/com/xingin/xhs/Shield.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/com/xingin/xhs/Shield.java) 小红书
- [src/test/java/com/xunmeng/pinduoduo/secure/DeviceNative.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/com/xunmeng/pinduoduo/secure/DeviceNative.java) 拼多多
- [src/test/java/com/mfw/tnative/AuthorizeHelper.java](https://github.com/zhkl0228/unidbg/blob/master/src/test/java/com/mfw/tnative/AuthorizeHelper.java)

## Features
- Emulation of the JNI Invocation API so JNI_OnLoad can be called.
- Support JavaVM, JNIEnv.
- Emulation of syscalls instruction.
- Support ARM32 and ARM64 bit ELF.
- Inline hook, thanks to HookZz.
- Import hook, thanks to xHook.
- Support simple debugger, instruction trace, memory read/write trace.

## TODO
- Working iOS emulation.
- ~~Support iOS objc.~~

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
