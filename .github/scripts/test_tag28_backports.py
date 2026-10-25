#!/usr/bin/env python3
"""Static regression guards for upstream Dopamine 3.0.12 backports.

These checks enforce presence and placement in RC7 sources, not iOS runtime behavior.
References: opa334/Dopamine commits 9ba0209 and 995c700.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]

daemon = (ROOT / "BaseBin/launchdhook/src/daemon_hook.m").read_text()
launch_section = daemon.split('if (!strcmp(key, "LaunchDaemons"))', 1)[1].split('else if (!strcmp(key, "Paths"))', 1)[0]
assert 'if (xpc_get_type(origXvalue) == XPC_TYPE_DICTIONARY)' in launch_section
assert 'xpc_dictionary_set_value(origXvalue, "/System/Library/LaunchDaemons/com.apple.mtmergeprops.plist", NULL);' in launch_section
assert launch_section.count('com.apple.mtmergeprops.plist') == 1
print("PASS: userspace reboot mtmergeprops registration skipped in launchd daemon dictionary (source guard)")

cfprefs = (ROOT / "BaseBin/rootlesshooks/cfprefsd.x").read_text()
whitelist = cfprefs.split('NSArray *additionalSystemPlistNames = @[', 1)[1].split('];', 1)[0]
for plist in ('ReportSystemMemory.plist', 'TokenBucketRateLimiter.plist', 'PerfPowerServices.plist'):
    assert whitelist.count('@"' + plist + '"') == 1, plist
assert 'return ![additionalSystemPlistNames containsObject:plistName];' in cfprefs
print("PASS: 3 system preference plists excluded from rootless redirect (source guard)")
