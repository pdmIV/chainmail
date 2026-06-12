"""Thin Paramiko wrapper for read-only command execution on the target.

Design notes:
* Authentication accepts either a password or a private key file (``-i``).
* ``run`` is fire-and-collect: it returns stdout/stderr/exit status and never
  raises on a non-zero exit, because enumeration commands routinely fail
  (permission denied, binary missing) and that is itself signal.
* Nothing here ever runs an escalation. The caller decides what to collect,
  and every command sent is a read/enumerate operation.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass

try:
    import paramiko
except ImportError as exc:  # pragma: no cover - dependency hint
    raise SystemExit(
        "paramiko is required. Install with: pip install -r requirements.txt"
    ) from exc


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_status: int

    @property
    def ok(self) -> bool:
        return self.exit_status == 0

    @property
    def out(self) -> str:
        """Best-effort combined text (stdout, falling back to stderr)."""
        return self.stdout if self.stdout.strip() else self.stderr


class SSHTarget:
    def __init__(
        self,
        host: str,
        user: str,
        port: int = 22,
        password: str | None = None,
        key_filename: str | None = None,
        key_passphrase: str | None = None,
        timeout: float = 15.0,
    ):
        self.host = host
        self.user = user
        self.port = port
        self._password = password
        self._key_filename = key_filename
        self._key_passphrase = key_passphrase
        self._timeout = timeout
        self._client: "paramiko.SSHClient | None" = None

    # -- lifecycle ---------------------------------------------------------
    def connect(self) -> None:
        client = paramiko.SSHClient()
        # Pentest context: we connect to arbitrary lab/target hosts, so we
        # accept unknown host keys rather than refusing. Operators who care
        # can pre-populate known_hosts and swap this policy out.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.user,
                password=self._password,
                key_filename=self._key_filename,
                passphrase=self._key_passphrase,
                timeout=self._timeout,
                allow_agent=True,
                look_for_keys=self._key_filename is None and self._password is None,
                banner_timeout=self._timeout,
                auth_timeout=self._timeout,
            )
        except paramiko.AuthenticationException as exc:
            raise ConnectionError(f"Authentication failed for {self.user}@{self.host}") from exc
        except (socket.timeout, socket.error) as exc:
            raise ConnectionError(f"Could not reach {self.host}:{self.port}: {exc}") from exc
        self._client = client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "SSHTarget":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- execution ---------------------------------------------------------
    def run(self, command: str, timeout: float | None = None) -> CommandResult:
        if self._client is None:
            raise RuntimeError("SSHTarget.run called before connect()")
        stdin, stdout, stderr = self._client.exec_command(
            command, timeout=timeout or self._timeout
        )
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        return CommandResult(command=command, stdout=out, stderr=err, exit_status=status)

    def run_first(self, *commands: str) -> CommandResult:
        """Try several equivalent commands, return the first that succeeds.

        Useful when target tooling varies (e.g. ``getcap`` may be absent).
        """
        last: CommandResult | None = None
        for cmd in commands:
            last = self.run(cmd)
            if last.ok and last.stdout.strip():
                return last
        return last  # type: ignore[return-value]
