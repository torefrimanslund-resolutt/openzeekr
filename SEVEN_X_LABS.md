# 7X Labs (read-only)

Controls → 7X Labs captures the untyped `data` payloads from the existing vehicle
capability, remote-control-state and vehicle-status GET endpoints. Unknown fields
are retained after redaction. No command, heartbeat, wake-up request, new endpoint,
or service-ID probe is involved. The dedicated API client omits HTTP body logging.

1. Park safely and capture **Baseline**.
2. Toggle one feature manually using the vehicle's own controls.
3. Tap **Compare now**. Repeat to compare against the same baseline.
4. **Baseline** replaces the reference; **Clear** cancels any pending capture and
   removes both snapshots. Data is held only in memory and is cleared when the
   Controls screen leaves composition or the configured vehicle/account/session changes.

Capture timestamps describe when cloud reads completed. The three reads are
sequential, not atomic; the cloud may return cached state. An unchanged or missing
field does not prove that a feature is unsupported. Failed sources are excluded
from comparisons and shown individually. All-source failure keeps previous data.

The panel exposes sanitized JSON and JSON Pointer key/value pairs (including array
indices, nulls and empty containers). Added, removed and changed values are shown;
research-related paths are highlighted. The four mode fields are surfaced when
present, without assigning undocumented meanings to their raw values.

VIN, location, user/device identifiers, credentials and other sensitive subtrees
are filtered before retention. Key/value descriptor records and embedded JSON
strings are also sanitized; known configured identifiers echoed in strings are
redacted. There is no export, clipboard, persistence, or raw-payload logging path.
This conservative filter is not a guarantee for every undocumented future schema.

`PCM` is a Parking Comfort research lead supplied for this investigation, not an
implemented command. Camp Mode control remains unknown. Cabin-light and direct
fan-speed controls remain unverified. This feature adds no command catalog entries.

Validation: run `gradlew.bat :core:testDebugUnitTest :app:assembleDebug :wear:assembleDebug`.
Live vehicle validation requires manual before/after captures; offline tests cover
redaction, flattening, type preservation, additions/removals, and partial failures.
