package com.github.unidbg.ios.ipa;

import com.alibaba.fastjson.JSON;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.file.ios.DarwinFileIO;

public class LoadedIpa {

    private final Emulator<DarwinFileIO> emulator;
    private final Module executable;
    private final String bundleIdentifier;
    private final String bundleVersion;

    LoadedIpa(Emulator<DarwinFileIO> emulator, Module executable, String bundleIdentifier, String bundleVersion) {
        this.emulator = emulator;
        this.executable = executable;
        this.bundleIdentifier = bundleIdentifier;
        this.bundleVersion = bundleVersion;
    }

    public String getBundleIdentifier() {
        return bundleIdentifier;
    }

    public String getBundleVersion() {
        return bundleVersion;
    }

    private boolean callFinishLaunchingWithOptions;

    public void setCallFinishLaunchingWithOptions(boolean callFinishLaunchingWithOptions) {
        this.callFinishLaunchingWithOptions = callFinishLaunchingWithOptions;
    }

    private String systemName;
    private String systemVersion;
    private String model;
    private String name;
    private String identifierForVendor;
    private String advertisingIdentifier;
    private String carrierName;

    public void callEntry() {
        ArgsRequest args = new ArgsRequest();
        args.setCallFinishLaunchingWithOptions(callFinishLaunchingWithOptions);
        args.setSystemName(systemName);
        args.setSystemVersion(systemVersion);
        args.setModel(model);
        args.setName(name);
        args.setIdentifierForVendor(identifierForVendor);
        args.setAdvertisingIdentifier(advertisingIdentifier);
        args.setCarrierName(carrierName);
        executable.callEntry(emulator, "-args", JSON.toJSONString(args));
    }

    public Module getExecutable() {
        return executable;
    }

    public Emulator<DarwinFileIO> getEmulator() {
        return emulator;
    }

    public void setSystemName(String systemName) {
        this.systemName = systemName;
    }

    public void setSystemVersion(String systemVersion) {
        this.systemVersion = systemVersion;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setIdentifierForVendor(String identifierForVendor) {
        this.identifierForVendor = identifierForVendor;
    }

    public void setAdvertisingIdentifier(String advertisingIdentifier) {
        this.advertisingIdentifier = advertisingIdentifier;
    }

    public void setCarrierName(String carrierName) {
        this.carrierName = carrierName;
    }
}
