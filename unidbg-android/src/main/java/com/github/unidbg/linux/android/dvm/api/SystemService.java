package com.github.unidbg.linux.android.dvm.api;

import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;

public class SystemService extends DvmObject<String> {

    public static final String WIFI_SERVICE = "wifi";
    public static final String CONNECTIVITY_SERVICE = "connectivity";
    public static final String TELEPHONY_SERVICE = "phone";
    public static final String ACCESSIBILITY_SERVICE = "accessibility";
    public static final String KEYGUARD_SERVICE = "keyguard";
    public static final String ACTIVITY_SERVICE = "activity";
    public static final String SENSOR_SERVICE = "sensor";
    public static final String INPUT_METHOD_SERVICE = "input_method";
    public static final String LOCATION_SERVICE = "location";
    public static final String WINDOW_SERVICE = "window";
    public static final String UI_MODE_SERVICE = "uimode";
    public static final String DISPLAY_SERVICE = "display";
    public static final String AUDIO_SERVICE = "audio";
    
    public SystemService(VM vm, String serviceName) {
        super(getObjectType(vm, serviceName), serviceName);
    }

    private static DvmClass getObjectType(VM vm, String serviceName) {
        switch (serviceName) {
            case TELEPHONY_SERVICE:
                return vm.resolveClass("android/telephony/TelephonyManager");
            case WIFI_SERVICE:
                return vm.resolveClass("android/net/wifi/WifiManager");
            case CONNECTIVITY_SERVICE:
                return vm.resolveClass("android/net/ConnectivityManager");
            case ACCESSIBILITY_SERVICE:
                return vm.resolveClass("android/view/accessibility/AccessibilityManager");
            case KEYGUARD_SERVICE:
                return vm.resolveClass("android/app/KeyguardManager");
            case ACTIVITY_SERVICE:
                return vm.resolveClass("android/os/BinderProxy"); // android/app/ActivityManager
            case SENSOR_SERVICE:
                return vm.resolveClass("android/hardware/SensorManager");
            case INPUT_METHOD_SERVICE:
                return vm.resolveClass("android/view/inputmethod/InputMethodManager");
            case LOCATION_SERVICE:
                return vm.resolveClass("android/location/LocationManager");
            case WINDOW_SERVICE:
                return vm.resolveClass("android/view/WindowManager");
            case UI_MODE_SERVICE:
                return vm.resolveClass("android/app/UiModeManager");
            case DISPLAY_SERVICE:
                return vm.resolveClass("android/hardware/display/DisplayManager");
            case AUDIO_SERVICE:
                return vm.resolveClass("android/media/AudioManager");
            default:
                throw new BackendException("service failed: " + serviceName);
        }
    }

}
