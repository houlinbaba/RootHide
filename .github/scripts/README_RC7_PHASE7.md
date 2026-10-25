# RC7 Phase 7 host validation

Run `python3 .github/scripts/test_rc7_phase7_crossaudit.py` from the project root.
This verifies actual systemhook/launchdhook compilation source paths and the
byte-for-byte preservation of 374 unmodified UI / licensing / Glass / package
assets relative to the originally uploaded RC7 source snapshot.

The test does not compile Apple Objective-C binaries, check a remote Git SHA,
or certify a TIPA / real iOS device.
