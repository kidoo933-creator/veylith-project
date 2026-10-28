# VEYLITH - Native Android Architecture & Build Documentation

**Product Name:** Veylith  
**Category:** AI-Powered Cybersecurity Investigation & Digital Forensics  
**Tagline:** See Deeper. Know More.  
**Platform Target:** Android 8.0+ (API Level 26+), Target SDK 35  

---

## 1. Architectural Overview

Veylith is engineered as a modern, defensible digital forensics and incident response (DFIR) platform adhering to strict enterprise standards:

- **UI Framework:** 100% Jetpack Compose with Material 3 design system.
- **Architecture:** Clean MVVM with Coroutines, StateFlow, and Repositories.
- **Local Persistence:** Room Database for persistent cases, evidence items, and cryptographic chain-of-custody audit trails.
- **Security Engineering:** Least privilege permissions (`INTERNET`, `ACCESS_NETWORK_STATE`), mandatory SSRF guard layer, deterministic Web Crypto SHA-256 calculation, and zero untrusted binary execution.
- **AI Integration Boundary:** Tool-oriented architecture integrating Google Gemini 4 Argon (`gemini-4-argon`) with `ThinkingLevel.HIGH` for deep forensic reasoning and ATT&CK mapping.

---

## 2. Project Directory Structure

```
android/
├── build.gradle.kts           # Root Gradle build script
├── settings.gradle.kts        # Repository management & module inclusion
└── app/
    ├── build.gradle.kts       # App-level dependencies (Room, Compose, OkHttp)
    └── src/
        ├── main/
        │   ├── AndroidManifest.xml   # Least-privilege manifest
        │   ├── java/com/veylith/app/
        │   │   ├── MainActivity.kt
        │   │   ├── VeylithApplication.kt
        │   │   ├── security/SsrfGuard.kt
        │   │   ├── forensics/
        │   │   │   ├── HashCalculator.kt
        │   │   │   └── EntropyCalculator.kt
        │   │   ├── data/local/
        │   │   │   ├── VeylithDatabase.kt
        │   │   │   ├── entity/CaseEntity.kt
        │   │   │   └── dao/CaseDao.kt
        │   │   └── ui/
        │   │       ├── navigation/NavGraph.kt
        │   │       ├── theme/Theme.kt
        │   │       └── screens/
        │   └── res/
        └── test/java/com/veylith/app/
            └── ForensicsEngineUnitTest.kt
```

---

## 3. How to Open and Build in Android Studio

1. **Prerequisites:**
   - Android Studio (Ladybug / Iguana 2024.1+ recommended).
   - JDK 17 or higher configured in Android Studio Gradle Settings.
   - Android SDK 35 with Build Tools 35.0.0.

2. **Open Project:**
   - Launch Android Studio.
   - Choose **File > Open** and select the `/android` directory.
   - Allow Gradle to sync dependencies automatically.

3. **Run Unit Tests:**
   Execute via CLI:
   ```bash
   ./gradlew test
   ```
   Or run the tests directly in Android Studio under `app/src/test`.

4. **Assemble Debug APK:**
   ```bash
   ./gradlew assembleDebug
   ```
   The resulting installable APK will be generated at:
   `app/build/outputs/apk/debug/app-debug.apk`

5. **Deploy to Connected Device or Emulator:**
   ```bash
   adb install -r app/build/outputs/apk/debug/app-debug.apk
   ```

---

## 4. Operational & Forensic Standards

- **[OBSERVED]:** Directly captured from verified tool output or cryptographic hash.
- **[CONFIRMED]:** Independently corroborated across multiple distinct evidence sources.
- **[INFERRED]:** Reasoned logically from recorded evidence.
- **[POTENTIAL]:** Plausible threat hypothesis requiring additional telemetry.
- **[UNKNOWN]:** Untested or inconclusive state.
- **Zero-Failure Fallback:** If cloud AI endpoints or network feeds are unreachable, local deterministic forensics workflows continue without interruption.
