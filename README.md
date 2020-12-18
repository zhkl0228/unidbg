# unidbg

Allows you to emulate an Android ARM32 and/or ARM64 native library, and an experimental  iOS ARM32 emulation.<br>

This is an educational project to learn more about the ELF file format and ARM assembly.

## License
- unidbg uses software libraries from [Apache Software Foundation](http://apache.org). 
- unidbg developer Idea enterprise licenses are supported by [Jetbrains](https://www.jetbrains.com?from=unidbg).
- [IntelliJ IDEA](https://www.jetbrains.com/idea?from=unidbg) can be used to edit unidbg sources.
- ![](assets/idea_logo.svg)

Simple tests under src/test directory
- [unidbg-android/src/test/java/com/bytedance/frameworks/core/encrypt/TTEncrypt.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/com/bytedance/frameworks/core/encrypt/TTEncrypt.java)  

![](assets/TTEncrypt.gif)
***
- [unidbg-android/src/test/java/com/sun/jna/JniDispatch32.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/com/sun/jna/JniDispatch32.java)  
![](assets/JniDispatch32.gif)
***
- [unidbg-android/src/test/java/com/sun/jna/JniDispatch64.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/com/sun/jna/JniDispatch64.java)  
![](assets/JniDispatch64.gif)
***
- [unidbg-android/src/test/java/org/telegram/messenger/Utilities32.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/org/telegram/messenger/Utilities32.java)  
![](assets/Utilities32.gif)
***
- [unidbg-android/src/test/java/org/telegram/messenger/Utilities64.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/org/telegram/messenger/Utilities64.java)  
![](assets/Utilities64.gif)

## More tests
- [unidbg-android/src/test/java/com/github/unidbg/android/QDReaderJni.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/com/github/unidbg/android/QDReaderJni.java)

## Features
- Emulation of the JNI Invocation API so JNI_OnLoad can be called.
- Support JavaVM, JNIEnv.
- Emulation of syscalls instruction.
- Support ARM32 and ARM64.
- Inline hook, thanks to [HookZz](https://github.com/jmpews/Dobby).
- Android import hook, thanks to [xHook](https://github.com/iqiyi/xHook).
- iOS [fishhook](https://github.com/facebook/fishhook) and substrate and [whale](https://github.com/asLody/whale) hook.
- Support simple console debugger, gdb stub, experimental IDA android debugger server, instruction trace, memory read/write trace.
- Support iOS objc and swift runtime.

## Thanks
- [unicorn](https://github.com/zhkl0228/unicorn)
- [dynarmic](https://github.com/MerryMage/dynarmic)
- [HookZz](https://github.com/jmpews/Dobby)
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
- [runtime_class-dump](https://github.com/Tyilo/runtime_class-dump)

## 在大佬的基础上增加了trace
相关代码在unidbg-api/src/main/java/king.trace中
使用方式如下

~~~java
//添加忽略trace的模块
GlobalData.ignoreModuleList.add("libc.so");
GlobalData.ignoreModuleList.add("libhookzz.so");
//添加内存监控，每个指令执行时，都查询该内存是否值有变化。比较消耗性能。
GlobalData.watch_address.put(0x401db840,"");
//dump ldr的数据。包括ldr赋值给寄存器的如果是指针，也会dump
GlobalData.is_dump_ldr=true;
//dump str的数据
GlobalData.is_dump_str=true;
KingTrace trace=new KingTrace(emulator);
trace.initialize(1,0,null);
emulator.getBackend().hook_add_new(trace,1,0,emulator);
~~~

trace的效果大致如下

~~~
>-----------------------------------------------------------------------------<
[23:25:53 634]watch_address:401db840 onchange, md5=526e01d14f11b9492f77e174187cccf2, hex=46f0c2bbd0b705006cfeffff70feffffb0fdffff2de9304806489c2406497844
size: 32
0000: 46 F0 C2 BB D0 B7 05 00 6C FE FF FF 70 FE FF FF    F.......l...p...
0010: B0 FD FF FF 2D E9 30 48 06 48 9C 24 06 49 78 44    ....-.0H.H.$.IxD
^-----------------------------------------------------------------------------^
[      libc++.so] [0x32820] [ 2d e9 30 48 ] 0x401db820: push.w {r4, r5, fp, lr}-----r4=0x0	r5=0x0		//r4=0x700000000

>-----------------------------------------------------------------------------<
[23:25:53 639]ldr_right_address:401db840 dump, md5=ef93abe822600c1f7853f7391442906b, hex=46f0c2bbd0b705006cfeffff70feffffb0fdffff2de9304806489c24064978440d182819fef740e80c3c14f10c0ff8d1
size: 48
0000: 46 F0 C2 BB D0 B7 05 00 6C FE FF FF 70 FE FF FF    F.......l...p...
0010: B0 FD FF FF 2D E9 30 48 06 48 9C 24 06 49 78 44    ....-.0H.H.$.IxD
0020: 0D 18 28 19 FE F7 40 E8 0C 3C 14 F1 0C 0F F8 D1    ..(...@..<......
^-----------------------------------------------------------------------------^
[      libc++.so] [0x32824] [       07 4d ] 0x401db824: ldr r5, [pc, #0x1c]-----r5=0x0	pc=0x401db824		//r5=0x70005b7d0

>-----------------------------------------------------------------------------<
[23:25:53 642]ldr_right_address:401db846 dump, md5=d31277769916b0ea11452a4a5fd365dc, hex=05006cfeffff70feffffb0fdffff2de9304806489c24064978440d182819fef740e80c3c14f10c0ff8d1bde830889ab7
size: 48
0000: 05 00 6C FE FF FF 70 FE FF FF B0 FD FF FF 2D E9    ..l...p.......-.
0010: 30 48 06 48 9C 24 06 49 78 44 0D 18 28 19 FE F7    0H.H.$.IxD..(...
0020: 40 E8 0C 3C 14 F1 0C 0F F8 D1 BD E8 30 88 9A B7    @..<........0...
^-----------------------------------------------------------------------------^
[      libc++.so] [0x32826] [       08 48 ] 0x401db826: ldr r0, [pc, #0x20]-----r0=0x0	pc=0x401db826		//r0=0x7fffffe6c
[      libc++.so] [0x32828] [       7d 44 ] 0x401db828: add r5, pc-----r5=0x5b7d0	pc=0x401db828		//r5=0x740236ffc
[      libc++.so] [0x3282c] [       20 46 ] 0x401db82c: mov r0, r4-----r0=0xfffffe6c	r4=0x40239040		//r0=0x740239040
[      libc++.so] [0x3282e] [ fe f7 3e e8 ] 0x401db82e: blx #0x401d98ac
[      libc++.so] [0x308ac] [ 00 c6 8f e2 ] 0x401d98ac: add ip, pc, #0, #12-----ip=0x40082908	pc=0x401d98ac		//sp=0x7bffff778
[      libc++.so] [0x308b0] [ 5d ca 8c e2 ] 0x401d98b0: add ip, ip, #0x5d000-----ip=0x401d98b4		//sp=0x1bffff778

>-----------------------------------------------------------------------------<
[23:25:53 660]ldr_right_address:40237584 dump, md5=7334f49b4d7a7548eb1c3356311f48eb, hex=f9fd1f40f5892140598a2140299d1f40d1142140d19f214031962140e5122040814a2040c1a02140d12b2040e18b2140
size: 48
0000: F9 FD 1F 40 F5 89 21 40 59 8A 21 40 29 9D 1F 40    ...@..!@Y.!@)..@
0010: D1 14 21 40 D1 9F 21 40 31 96 21 40 E5 12 20 40    ..!@..!@1.!@.. @
0020: 81 4A 20 40 C1 A0 21 40 D1 2B 20 40 E1 8B 21 40    .J @..!@.+ @..!@
^-----------------------------------------------------------------------------^
[      libc++.so] [0x308b4] [ d0 fc bc e5 ] 0x401d98b4: ldr pc, [ip, #0xcd0]!-----ip=0x402368b4	pc=0x401d98b4		//sp=0xbffff778

>-----------------------------------------------------------------------------<
[23:25:53 663]ldr_left_address:bffff778 dump, md5=f0f77a5db1c6c46c94ec8a0ea7e43f56, hex=0000000000000000000000000000ffff000000000000000000fcffbf0000000000000000000000000000000000000000
size: 48
0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF    ................
0010: 00 00 00 00 00 00 00 00 00 FC FF BF 00 00 00 00    ................
0020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
^-----------------------------------------------------------------------------^
[      libc++.so] [0x56df8] [ 2d e9 f0 4f ] 0x401ffdf8: push.w {r4, r5, r6, r7, r8, sb, sl, fp, lr}-----r4=0x40239040	r5=0x40236ffc	r6=0x0	r7=0x0	r8=0x0		//r4=0x40239040
[      libc++.so] [0x56dfc] [       81 b0 ] 0x401ffdfc: sub sp, #4-----sp=0xbffff754		//sp=0xbffff750
~~~

