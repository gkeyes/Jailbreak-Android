# Lhasa26-Android

Clean-room Android refactor of the attached `lhasa26-v4.17-xmz.apk`.

The application layer is rewritten in Java with a separated workflow engine, Shizuku command adapter, asset deployer, device information model, log export, and programmatic UI. The supplied device-specific native payloads are kept as opaque assets so the first refactor can preserve the original runtime behavior while the application code is independently maintainable.

## Current scope

- Android application ID: `com.gkeyes.lhasa26`
- Minimum SDK: 26
- Target / compile SDK: 35
- Shizuku API: 13.1.5
- Supported kernel profiles are the three profiles shipped in the source APK.
- The release build is intentionally unsigned by the repository; signing belongs in the local or CI release workflow.

## Build

```bash
export ANDROID_SDK_ROOT=/path/to/android-sdk
./gradlew :app:assembleDebug
```

The runtime payloads under `app/src/main/assets/` came from the user-supplied APK and are device/kernel-specific. Do not publish this repository without confirming the applicable rights, device scope, and disclosure policy.
