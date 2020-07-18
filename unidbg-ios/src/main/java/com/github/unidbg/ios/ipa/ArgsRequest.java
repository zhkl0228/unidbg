package com.github.unidbg.ios.ipa;

public class ArgsRequest {

    private boolean callFinishLaunchingWithOptions;

    public boolean isCallFinishLaunchingWithOptions() {
        return callFinishLaunchingWithOptions;
    }

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

    public String getSystemName() {
        return systemName;
    }

    public void setSystemName(String systemName) {
        this.systemName = systemName;
    }

    public String getSystemVersion() {
        return systemVersion;
    }

    public void setSystemVersion(String systemVersion) {
        this.systemVersion = systemVersion;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIdentifierForVendor() {
        return identifierForVendor;
    }

    public void setIdentifierForVendor(String identifierForVendor) {
        this.identifierForVendor = identifierForVendor;
    }

    public String getAdvertisingIdentifier() {
        return advertisingIdentifier;
    }

    public void setAdvertisingIdentifier(String advertisingIdentifier) {
        this.advertisingIdentifier = advertisingIdentifier;
    }

    public String getCarrierName() {
        return carrierName;
    }

    public void setCarrierName(String carrierName) {
        this.carrierName = carrierName;
    }
}
