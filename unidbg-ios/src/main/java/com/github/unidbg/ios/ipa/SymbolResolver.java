package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.Arm64Hook;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmHook;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.arm.context.EditableArm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.ios.struct.DispatchSourceType;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class SymbolResolver implements HookListener {

    private static final Logger log = LoggerFactory.getLogger(SymbolResolver.class);

    private final Emulator<DarwinFileIO> emulator;
    private UnidbgPointer _os_unfair_lock_lock, _os_unfair_lock_unlock;
    private UnidbgPointer _objc_readClassPair;
    private UnidbgPointer _objc_unsafeClaimAutoreleasedReturnValue;
    private UnidbgPointer __tlv_bootstrap;

    private UnidbgPointer __dispatch_source_type_memorypressure;
    private UnidbgPointer dispatch_source_type_memorypressure_init;
    private UnidbgPointer dispatch_queue_attr_make_with_qos_class;
    private UnidbgPointer dispatch_queue_attr_make_with_autorelease_frequency;
    private UnidbgPointer dispatch_queue_attr_make_initially_inactive;
    private UnidbgPointer ___chkstk_darwin;
    private UnidbgPointer _clock_gettime;
    private UnidbgPointer _pthread_attr_set_qos_class_np;
    private UnidbgPointer _pthread_set_qos_class_self_np;
    private UnidbgPointer _qos_class_self;
    private UnidbgPointer _dispatch_assert_queue$V2;
    private UnidbgPointer _dispatch_assert_queue_not$V2;
    private UnidbgPointer _dispatch_block_create;
    private UnidbgPointer _dispatch_get_global_queue;
    private UnidbgPointer _dispatch_group_async;

    public SymbolResolver(Emulator<DarwinFileIO> emulator) {
        this.emulator = emulator;
    }

    private final long nanoTime = System.nanoTime();

    private static final int CLOCK_REALTIME = 0;
    private static final int CLOCK_MONOTONIC_RAW = 4;
    private static final int CLOCK_MONOTONIC = 6;

    private long old_dispatch_sync;

    @Override
    public long hook(final SvcMemory svcMemory, String libraryName, String symbolName, final long old) {
        if ("_dispatch_sync".equals(symbolName) && "libdispatch.dylib".equals(libraryName)) {
            old_dispatch_sync = old;
        }
        if ("_dispatch_group_async".equals(symbolName)) {
            if (_dispatch_group_async == null) {
                if (old_dispatch_sync == 0L) {
                    Module dispatch = emulator.getMemory().findModule("libdispatch.dylib");
                    Symbol symbol = dispatch.findSymbolByName("_dispatch_sync", false);
                    old_dispatch_sync = symbol.getAddress();
                }
                if (emulator.is64Bit()) {
                    _dispatch_group_async = svcMemory.registerSvc(new Arm64Hook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            EditableArm64RegisterContext context = emulator.getContext();
                            Pointer group = context.getPointerArg(0);
                            UnidbgPointer queue = context.getPointerArg(1);
                            UnidbgPointer block = context.getPointerArg(2);
                            log.info("Patch64 dispatch_group_async to dispatch_sync group={}, queue={}, block={}, LR={}", group, queue, block, context.getLRPointer());
                            context.setXLong(0, queue == null ? 0 : queue.peer);
                            context.setXLong(1, block == null ? 0 : block.peer);
                            return HookStatus.RET(emulator, old_dispatch_sync);
                        }
                    });
                } else {
                    _dispatch_group_async = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            EditableArm32RegisterContext context = emulator.getContext();
                            Pointer group = context.getPointerArg(0);
                            UnidbgPointer queue = context.getPointerArg(1);
                            UnidbgPointer block = context.getPointerArg(2);
                            log.info("Patch32 dispatch_group_async to dispatch_sync group={}, queue={}, block={}, LR={}", group, queue, block, context.getLRPointer());
                            context.setR0(queue == null ? 0 : queue.toIntPeer());
                            context.setR1(block == null ? 0 : block.toIntPeer());
                            return HookStatus.RET(emulator, old_dispatch_sync);
                        }
                    });
                }
            }
            return _dispatch_group_async.peer;
        }
        if ("_dispatch_get_global_queue".equals(symbolName)) {
            if (_dispatch_get_global_queue == null) {
                if (emulator.is64Bit()) {
                    _dispatch_get_global_queue = svcMemory.registerSvc(new Arm64Hook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            EditableArm64RegisterContext context = emulator.getContext();
                            int identifier = context.getIntArg(0);
                            int flags = context.getIntArg(1);
                            if (log.isDebugEnabled()) {
                                log.debug("dispatch_get_global_queue64 identifier=0x{}, flags=0x{}", Integer.toHexString(identifier), Integer.toHexString(flags));
                            }
                            int QOS_CLASS_USER_INTERACTIVE = 0x21;
                            int QOS_CLASS_USER_INITIATED = 0x19;
                            int QOS_CLASS_DEFAULT = 0x15;
                            int QOS_CLASS_UTILITY = 0x11;
                            int QOS_CLASS_BACKGROUND = 0x9;
                            int DISPATCH_QUEUE_PRIORITY_DEFAULT = 0x0;
                            if (identifier == QOS_CLASS_BACKGROUND ||
                                    identifier == QOS_CLASS_DEFAULT ||
                                    identifier == QOS_CLASS_USER_INITIATED ||
                                    identifier == QOS_CLASS_UTILITY ||
                                    identifier == QOS_CLASS_USER_INTERACTIVE) {
                                context.setXLong(0, DISPATCH_QUEUE_PRIORITY_DEFAULT);
                            }
                            return HookStatus.RET(emulator, old);
                        }
                    });
                } else {
                    _dispatch_get_global_queue = svcMemory.registerSvc(new ArmHook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            EditableArm32RegisterContext context = emulator.getContext();
                            int identifier = context.getIntArg(0);
                            int flags = context.getIntArg(1);
                            if (log.isDebugEnabled()) {
                                log.debug("dispatch_get_global_queue32 identifier=0x{}, flags=0x{}", Integer.toHexString(identifier), Integer.toHexString(flags));
                            }
                            int QOS_CLASS_USER_INTERACTIVE = 0x21;
                            int QOS_CLASS_USER_INITIATED = 0x19;
                            int QOS_CLASS_DEFAULT = 0x15;
                            int QOS_CLASS_UTILITY = 0x11;
                            int QOS_CLASS_BACKGROUND = 0x9;
                            int DISPATCH_QUEUE_PRIORITY_DEFAULT = 0x0;
                            if (identifier == QOS_CLASS_BACKGROUND ||
                                    identifier == QOS_CLASS_DEFAULT ||
                                    identifier == QOS_CLASS_USER_INITIATED ||
                                    identifier == QOS_CLASS_UTILITY ||
                                    identifier == QOS_CLASS_USER_INTERACTIVE) {
                                context.setR0(DISPATCH_QUEUE_PRIORITY_DEFAULT);
                            }
                            return HookStatus.RET(emulator, old);
                        }
                    });
                }
            }
            return _dispatch_get_global_queue.peer;
        }
        if ("_dispatch_block_create".equals(symbolName) && emulator.is64Bit()) {
            if (_dispatch_block_create == null) {
                _dispatch_block_create = svcMemory.registerSvc(new Arm64Svc("dispatch_block_create") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        int flags = context.getIntArg(0);
                        UnidbgPointer block = context.getPointerArg(1);
                        log.info("_dispatch_block_create flags=0x{}, block={}", Integer.toHexString(flags), block);
                        return block == null ? 0 : block.peer;
                    }
                });
            }
            return _dispatch_block_create.peer;
        }
        if ("_dispatch_assert_queue$V2".equals(symbolName) && emulator.is64Bit()) {
            if (_dispatch_assert_queue$V2 == null) {
                _dispatch_assert_queue$V2 = svcMemory.registerSvc(new Arm64Svc("dispatch_assert_queue$V2") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        log.info("_dispatch_assert_queue$V2 queue={}", context.getPointerArg(0));
                        return 0;
                    }
                });
            }
            return _dispatch_assert_queue$V2.peer;
        }
        if ("_dispatch_assert_queue_not$V2".equals(symbolName)) {
            if (_dispatch_assert_queue_not$V2 == null) {
                _dispatch_assert_queue_not$V2 = svcMemory.registerSvc(new Arm64Svc("dispatch_assert_queue_not$V2") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        log.info("_dispatch_assert_queue_not$V2 queue={}", context.getPointerArg(0));
                        return 0;
                    }
                });
            }
            return _dispatch_assert_queue_not$V2.peer;
        }
        if ("_qos_class_self".equals(symbolName) && emulator.is64Bit()) {
            if (_qos_class_self == null) {
                _qos_class_self = svcMemory.registerSvc(new Arm64Svc("qos_class_self") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        log.info("_qos_class_self");
                        return 0;
                    }
                });
            }
            return _qos_class_self.peer;
        }
        if ("_pthread_set_qos_class_self_np".equals(symbolName) && emulator.is64Bit()) {
            if (_pthread_set_qos_class_self_np == null) {
                _pthread_set_qos_class_self_np = svcMemory.registerSvc(new Arm64Svc("pthread_set_qos_class_self_np") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        int __qos_class = context.getIntArg(0);
                        int __relative_priority = context.getIntArg(1);
                        if (log.isDebugEnabled()) {
                            log.debug("_pthread_set_qos_class_self_np __qos_class={}, __relative_priority={}", __qos_class, __relative_priority);
                        }
                        return 0;
                    }
                });
            }
            return _pthread_set_qos_class_self_np.peer;
        }
        if ("_pthread_attr_set_qos_class_np".equals(symbolName) && emulator.is64Bit()) {
            if (_pthread_attr_set_qos_class_np == null) {
                _pthread_attr_set_qos_class_np = svcMemory.registerSvc(new Arm64Svc("pthread_attr_set_qos_class_np") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        Pointer __attr = context.getPointerArg(0);
                        int __qos_class = context.getIntArg(1);
                        int __relative_priority = context.getIntArg(2);
                        if (log.isDebugEnabled()) {
                            log.debug("_pthread_attr_set_qos_class_np __attr={}, __qos_class={}, __relative_priority={}", __attr, __qos_class, __relative_priority);
                        }
                        return 0;
                    }
                });
            }
            return _pthread_attr_set_qos_class_np.peer;
        }
        if ("_clock_gettime".equals(symbolName) && emulator.is64Bit()) {
            if (_clock_gettime == null) {
                _clock_gettime = svcMemory.registerSvc(new Arm64Svc("clock_gettime") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        int clk_id = context.getIntArg(0);
                        Pointer tp = context.getPointerArg(1);
                        long offset = clk_id == CLOCK_REALTIME ? System.currentTimeMillis() * 1000000L : System.nanoTime() - nanoTime;
                        long tv_sec = offset / 1000000000L;
                        long tv_nsec = offset % 1000000000L;
                        if (log.isDebugEnabled()) {
                            log.debug("clock_gettime clk_id={}, tp={}, offset={}, tv_sec={}, tv_nsec={}", clk_id, tp, offset, tv_sec, tv_nsec);
                        }
                        switch (clk_id) {
                            case CLOCK_REALTIME:
                            case CLOCK_MONOTONIC:
                            case CLOCK_MONOTONIC_RAW:
                                tp.setLong(0, tv_sec);
                                tp.setLong(8, tv_nsec);
                                return 0;
                        }
                        throw new UnsupportedOperationException("clk_id=" + clk_id);
                    }
                });
            }
            return _clock_gettime.peer;
        }
        if ("___chkstk_darwin".equals(symbolName) && emulator.is64Bit()) {
            if (___chkstk_darwin == null) {
                ___chkstk_darwin = svcMemory.registerSvc(new Arm64Svc("chkstk_darwin") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return emulator.getContext().getLongArg(0);
                    }
                });
            }
            return ___chkstk_darwin.peer;
        }
        if ("_dispatch_queue_attr_make_with_qos_class".equals(symbolName) && emulator.is64Bit()) {
            if (dispatch_queue_attr_make_with_qos_class == null) {
                dispatch_queue_attr_make_with_qos_class = svcMemory.registerSvc(new Arm64Svc("dispatch_queue_attr_make_with_qos_class") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        UnidbgPointer attr = context.getPointerArg(0);
//                        System.out.println("dispatch_queue_attr_make_with_qos_class attr=" + attr);
                        return attr == null ? 0 : attr.peer;
                    }
                });
            }
            return dispatch_queue_attr_make_with_qos_class.peer;
        }
        if ("_dispatch_queue_attr_make_with_autorelease_frequency".equals(symbolName) && emulator.is64Bit()) {
            if (dispatch_queue_attr_make_with_autorelease_frequency == null) {
                dispatch_queue_attr_make_with_autorelease_frequency = svcMemory.registerSvc(new Arm64Svc("dispatch_queue_attr_make_with_autorelease_frequency") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        UnidbgPointer attr = context.getPointerArg(0);
                        return attr == null ? 0 : attr.peer;
                    }
                });
            }
            return dispatch_queue_attr_make_with_autorelease_frequency.peer;
        }
        if ("_dispatch_queue_attr_make_initially_inactive".equals(symbolName) && emulator.is64Bit()) {
            if (dispatch_queue_attr_make_initially_inactive == null) {
                dispatch_queue_attr_make_initially_inactive = svcMemory.registerSvc(new Arm64Svc("dispatch_queue_attr_make_initially_inactive") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        UnidbgPointer attr = context.getPointerArg(0);
//                        System.out.println("dispatch_queue_attr_make_initially_inactive attr=" + attr);
                        return attr == null ? 0 : attr.peer;
                    }
                });
            }
            return dispatch_queue_attr_make_initially_inactive.peer;
        }
        if ("__dispatch_source_type_memorypressure".equals(symbolName) && emulator.is64Bit()) {
            if (dispatch_source_type_memorypressure_init == null) {
                dispatch_source_type_memorypressure_init = svcMemory.registerSvc(new Arm64Svc("dispatch_source_type_memorypressure") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        System.out.println("dispatch_source_type_memorypressure_init");
                        return 0;
                    }
                });
            }
            if (__dispatch_source_type_memorypressure == null) {
                final short EVFILT_MEMORYSTATUS = (-14); /* Memorystatus events */
                final short EV_DISPATCH = 0x0080; /* disable event after reporting */
                final int NOTE_MEMORYSTATUS_PRESSURE_NORMAL = 0x00000001; /* system memory pressure has returned to normal */
                final int NOTE_MEMORYSTATUS_PRESSURE_WARN = 0x00000002; /* system memory pressure has changed to the warning state */
                final int NOTE_MEMORYSTATUS_PRESSURE_CRITICAL = 0x00000004; /* system memory pressure has changed to the critical state */
                __dispatch_source_type_memorypressure = svcMemory.allocate(128, "__dispatch_source_type_memorypressure");
                DispatchSourceType dispatchSourceType = new DispatchSourceType(__dispatch_source_type_memorypressure);
                dispatchSourceType.ke.filter = EVFILT_MEMORYSTATUS;
                dispatchSourceType.ke.flags = EV_DISPATCH;
                dispatchSourceType.mask = NOTE_MEMORYSTATUS_PRESSURE_NORMAL | NOTE_MEMORYSTATUS_PRESSURE_WARN | NOTE_MEMORYSTATUS_PRESSURE_CRITICAL;
                dispatchSourceType.init = dispatch_source_type_memorypressure_init.peer;
                dispatchSourceType.pack();
            }
            return __dispatch_source_type_memorypressure.peer;
        }
        if ("_objc_unsafeClaimAutoreleasedReturnValue".equals(symbolName)) {
            if (_objc_unsafeClaimAutoreleasedReturnValue == null) {
                _objc_unsafeClaimAutoreleasedReturnValue = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc("objc_unsafeClaimAutoreleasedReturnValue") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        return context.getLongArg(0);
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        return context.getIntArg(0);
                    }
                });
            }
            return _objc_unsafeClaimAutoreleasedReturnValue.peer;
        }
        if ("_os_unfair_lock_lock".equals(symbolName)) {
            if (_os_unfair_lock_lock == null) {
                _os_unfair_lock_lock = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc("os_unfair_lock_lock") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                });
            }
            return _os_unfair_lock_lock.peer;
        }
        if ("_os_unfair_lock_unlock".equals(symbolName)) {
            if (_os_unfair_lock_unlock == null) {
                _os_unfair_lock_unlock = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc("os_unfair_lock_unlock") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        return 0;
                    }
                });
            }
            return _os_unfair_lock_unlock.peer;
        }
        if ("__tlv_bootstrap".equals(symbolName)) {
            if (__tlv_bootstrap == null) {
                __tlv_bootstrap = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc("tlv_bootstrap") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        RegisterContext context = emulator.getContext();
                        UnidbgPointer self = context.getPointerArg(0);
                        UnidbgPointer var = self.getPointer(8);
                        if (var == null) {
                            long size = self.getLong(16);
                            MemoryBlock block = emulator.getMemory().malloc((int) size, true);
                            var = block.getPointer();
                            self.setPointer(8, var);
                        }
                        return var.peer;
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        throw new UnsupportedOperationException();
                    }
                });
            }
            return __tlv_bootstrap.peer;
        }
        if ("_objc_readClassPair".equals(symbolName)) {
            if (_objc_readClassPair == null) {
                _objc_readClassPair = svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc("objc_readClassPair") {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                    "nop",
                                    "ret"));
                            byte[] code = encoded.getMachineCode();
                            UnidbgPointer pointer = svcMemory.allocate(code.length, "objc_readClassPair");
                            pointer.write(0, code, 0, code.length);
                            return pointer;
                        }
                    }
                } : new ArmSvc() {
                    @Override
                    public long handle(Emulator<?> emulator) {
                        throw new UnsupportedOperationException();
                    }
                    @Override
                    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                            KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                    "nop",
                                    "bx lr"));
                            byte[] code = encoded.getMachineCode();
                            UnidbgPointer pointer = svcMemory.allocate(code.length, "objc_readClassPair");
                            pointer.write(0, code, 0, code.length);
                            return pointer;
                        }
                    }
                });
            }
            return old == WEAK_BIND ? _objc_readClassPair.peer : 0;
        }
        return 0;
    }
}
