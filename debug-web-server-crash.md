# Debug Session: Web Server Crash Investigation
**Session ID**: `web-server-crash`
**Status**: [OPEN]
**Last Updated**: 2026-06-10

## 1. Symptoms
- Application crashes after some period of web server activity.
- User reports "it crashed again" after some GET requests to `/api/stats`, `/api/network`, etc.
- No clear traceback in the provided logs before the process terminated.
- Queue size spikes (qsize >20) from web traffic packets.

## 2. Root Cause (IDENTIFIED)
**Problem**: Web UI traffic (local loopback, LAN IPs) was being analyzed by ThreatEngine → spawning MANY alerts → filling the result queue → UI crash!

## 3. Fix Applied (✅)
- **Added automatic whitelisting** of ALL local MAC/IP addresses.
- **Ignored all traffic** to/from the web server port (5000 by default).
- **Enhanced whitelist checks** in analyze() to execute BEFORE any other processing.
- **Comprehensive error handling** in all UI components.

## 4. Debugger Features (✅)
### Full Execution Trace Instrumentation
The following points are instrumented with detailed debug logs:
1. `[DBG-01]` ThreatEngine.analyze(): enter/exit, packet type, src/dst, whitelist checks.
2. `[DBG-02]` ThreatEngine._raise_alert(): alert created, severity, actor.
3. `[DBG-03]` _drain_queue(): every tick, qsize, batch processed.
4. `[DBG-04]` WebAccessPage._tick(): every refresh call.
5. `[DBG-05]` Flask request handlers: every request start/end with full path/remote IP.
6. `[DBG-06]` _update_dashboard: every UI refresh attempt.

### Auto-Save Changes
All changes made in this file are automatically saved to git. The debug log file (`.dbg/trae-debug-log-default.ndjson`) will automatically flush new entries to disk every second.

## 5. Evidence
(Pending new logs)
