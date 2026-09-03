"""Threading helpers.

The controller runs on ordinary OS threads. This module exists so that code
written against a green-thread hub can move over one import at a time; new
code should use :mod:`threading` and :mod:`queue` directly.
"""

# Copyright (C) 2026 The c65sdn Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import threading
import time
from queue import Empty, Queue

__all__ = [
    "Empty",
    "Queue",
    "QueueEmpty",
    "joinall",
    "kill",
    "sleep",
    "spawn",
    "spawn_after",
]

QueueEmpty = Empty


def spawn(func, *args, **kwargs):
    """Run ``func`` on a daemon thread and return the thread.

    Daemon, so that a background loop never keeps the process alive at exit.
    """
    thread = threading.Thread(
        target=func, args=args, kwargs=kwargs, name=getattr(func, "__name__", None)
    )
    thread.daemon = True
    thread.start()
    return thread


def spawn_after(seconds, func, *args, **kwargs):
    """Run ``func`` on a daemon timer thread after ``seconds``."""
    timer = threading.Timer(seconds, func, args=args, kwargs=kwargs)
    timer.daemon = True
    timer.start()
    return timer


def joinall(threads):
    """Wait for every thread in ``threads``."""
    for thread in threads:
        if thread is not threading.current_thread():
            thread.join()


def kill(thread):  # pylint: disable=unused-argument
    """No-op: an OS thread cannot be killed from outside.

    Present so that shutdown paths written against a green-thread hub keep
    working. Threads spawned here are daemons, so the process still exits;
    a loop that must stop early needs its own stop signal.
    """


sleep = time.sleep
