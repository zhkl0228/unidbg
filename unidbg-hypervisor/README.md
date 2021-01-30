# Apple silicon hypervisor backend

Allows you to emulate Android ARM64 native library on Apple Silicon.<br>

## Sign the arm64 java binary
```
cd unidbg-hypervisor/assets
sudo ./ldid -M -Shypervisor.entitlements "$JAVA_HOME"/bin/java
sudo ./ldid -M -Shypervisor.entitlements "$JAVA_HOME"/jre/bin/java
```
