# unidbg-hypervisor

Allows you to emulate an Android ARM64 native library on Apple Silicon.<br>

## Sign the arm64 java binary
codesign --entitlements unidbg-hypervisor/src/main/native/hypervisor/hypervisor.entitlements --force -s - "$JAVA_HOME"/bin/java
