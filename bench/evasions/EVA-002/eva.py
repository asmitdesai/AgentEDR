"""EVA-002: main thread exits first (review NEW-2, ADR 0001).

Run as a process inside an agent session. The main thread calls
pthread_exit() while a worker keeps running and then executes a command. The
M0 sensor ended the tag on the main thread's exit, so the worker's command was
invisible and a false EXIT was emitted. Expected: the worker's command carries
the session id, and exactly one EXIT follows it.

Optional argument: an exit status for the worker to end the process with
(os._exit), instead of returning normally.

ctypes releases the GIL around foreign calls, so the worker can still run
Python code after the main thread has left through pthread_exit().
"""

import ctypes
import os
import sys
import threading
import time

code = int(sys.argv[1]) if len(sys.argv) > 1 else None


def worker() -> None:
    time.sleep(0.3)
    os.system("/bin/true eva002_marker")
    if code is not None:
        os._exit(code)


threading.Thread(target=worker).start()
ctypes.CDLL(None).pthread_exit(None)
