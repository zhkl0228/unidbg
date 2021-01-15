# unidbg-hypervisor

Allows you to emulate an Android ARM64 native library on Apple Silicon.<br>

## Sign the arm64 java binary
cd unidbg-hypervisor/src/main/native/hypervisor
sudo ./ldid -M -Shypervisor.entitlements "$JAVA_HOME"/bin/java
