"""EVA-001: exec from a worker thread (review NEW-1, ADR 0001).

Run as a process inside an agent session. A worker thread calls execv. The
kernel's de_thread() kills the old main thread before the exec completes; the
M0 sensor ended the tag on that exit, so the new image and its children were
invisible. Expected: every exec below carries the session id.
"""

import os
import threading


def worker() -> None:
    os.execv("/bin/sh", ["sh", "-c", "/bin/true eva001_exec_marker; /bin/true eva001_child_marker"])


t = threading.Thread(target=worker)
t.start()
t.join()
