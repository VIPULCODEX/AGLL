# Test applications

Two small Android projects used to test AGLL under known conditions. Both are
research fixtures: they cannot be used as malware and are not meant to be
installed on a real device.

| | SyntheticMalApp | RealisticMalApp |
|---|---|---|
| Methods | 32 | 35 |
| Ground-truth methods | 8 | 8 |
| Purpose | An inert app with no sensitive API calls, to see how each system behaves when there is nothing real to find. | An app whose payload methods call real but harmless APIs, to see whether narrowing recovers them. |
| Behavior categories | 1, 2, 6, 11 | 1, 2, 7, 11 |
| Entry points | `MainActivity` | `MainActivity`, `SyncReceiver`, `MaintenanceService` |

Both apps route their scenario methods through a `ScenarioRouter` that calls
anonymous `Runnable` callbacks. That keeps the call graph free of framework
registration and exercises the listener-dispatch edges added in
`src/agll/callgraph.py`.

## Safety boundary

Neither manifest declares `SEND_SMS`, `READ_SMS`, `RECEIVE_SMS`,
`BIND_ACCESSIBILITY_SERVICE` or `INTERNET`, and `verify_manifest.py` in each
folder checks this along with the ground-truth manifest.

- SyntheticMalApp calls no sensitive API at all. Its scenario classes only
  record symbolic event names in memory. The labels in its ground-truth file
  describe simulated intent and are not evidence that the APK is malicious.
- RealisticMalApp calls real APIs for location, contacts, the call log, a
  telephony identifier, a root-binary check, a write to its own private storage,
  and hiding its own launcher component. It cannot message anyone, send data
  over a network or control other apps. In the worst case it reads data that is
  already on the device and keeps it in its own private storage.

## Building

Build only in an isolated Android development environment with the Android SDK
installed:

```
gradle :app:assembleDebug
```

No APK is included. After building, decompile the APK with apktool. Stage 2
reads method bodies from that smali tree, and the ground-truth descriptors
should be verified against it. `RealisticMalApp/ground_truth_manifest.frozen.json`
is the descriptor-verified copy for that app. SyntheticMalApp only has the
source-level manifest, so its ground truth was not checked against compiled
bytecode; this is listed as a limitation in the paper.

## Files

```
<App>/
├── app/src/main/                  Android sources and manifest
├── build.gradle, settings.gradle
├── ground_truth_manifest.json     source-level manifest
├── ground_truth_manifest.frozen.json   RealisticMalApp only, checked against bytecode
└── verify_manifest.py
```
