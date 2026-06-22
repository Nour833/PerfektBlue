# perfektblue-can

Optional passive CAN capture analysis for PerfektBlue.

The plugin parses candump text captures and reports frame counts, payload lengths, changing
bytes, unique payloads, and per-byte entropy. It is kept separate so the Bluetooth framework
does not require CAN libraries or hardware.

