# Apple silicon hypervisor backend

Allows you to emulate Android and iOS ARM64 native library on Apple Silicon.<br>

## Sign the arm64 java binary
```
cd backend/hypervisor/assets
sudo ./ldid -M -Shypervisor.entitlements "$JAVA_HOME"/bin/java
sudo ./ldid -M -Shypervisor.entitlements "$JAVA_HOME"/jre/bin/java
```
