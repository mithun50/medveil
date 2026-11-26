"""Process guards: secret handling, no network, PII-free error output.

* RAKSHA_SECRET is read once and removed from os.environ.
* Any socket connect raises, so an accidental network call fails loudly and offline.
* Uncaught exceptions print only their class name: exception messages can carry
  file content (a KeyError on a patient name, for example).
"""
from __future__ import annotations

import os
import socket
import sys
import threading


class NetworkBlocked(RuntimeError):
    pass


def _blocked(*_a, **_k):
    raise NetworkBlocked("network disabled")


def block_network() -> None:
    socket.socket.connect = _blocked          # type: ignore[assignment]
    socket.socket.connect_ex = _blocked       # type: ignore[assignment]
    socket.create_connection = _blocked       # type: ignore[assignment]
    socket.getaddrinfo = _blocked             # type: ignore[assignment]


def _hook(exc_type, exc, tb):  # noqa: ARG001
    sys.stderr.write(f"medveil: fatal {exc_type.__name__}\n")


def _thread_hook(args):
    sys.stderr.write(f"medveil: thread error {args.exc_type.__name__}\n")


def install_hooks() -> None:
    sys.excepthook = _hook
    threading.excepthook = _thread_hook
    import warnings
    warnings.simplefilter("ignore")


def take_secret() -> bytes | None:
    val = os.environ.pop("RAKSHA_SECRET", None)
    if not val:
        return None
    return val.encode("utf-8")


def take_vault_secret() -> bytes | None:
    val = os.environ.pop("RAKSHA_VAULT_KEY", None)
    return val.encode("utf-8") if val else None
