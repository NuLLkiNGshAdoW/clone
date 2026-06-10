# Debug Session: Web Server Crash Investigation
**Session ID**: `web-server-crash`
**Status**: [OPEN]

## 1. Symptoms
- Application crashes after some period of web server activity.
- User reports "it crashed again" after some GET requests to `/api/stats`, `/api/network`, etc.
- No clear traceback in the provided logs before the process terminated.

## 2. Hypotheses
1. **Thread Safety Issue**: Race condition in `_drain_queue` or `api_stats` when accessing shared engine state (alerts, stats) leading to a segmentation fault or unhandled exception.
2. **Resource Exhaustion**: Memory leak or handle leak in the Flask request handlers causing the OS to kill the process.
3. **Tkinter Main Thread Violation**: A background thread (Flask or ThreatEngine) is attempting to modify UI elements directly without using `after()` or proper synchronization.
4. **Deadlock**: Circular dependency between `engine.lock` and `web_lock` causing the app to freeze and potentially be terminated by the user or OS.

## 3. Observation Points
- `[OP-1]` Flask request start/end in `_build_flask_app`.
- `[OP-2]` UI update loop in `_drain_queue` and `WebAccessPage._tick`.
- `[OP-3]` ThreatEngine alert raising and analysis loops.

## 4. Evidence
(Pending logs)
