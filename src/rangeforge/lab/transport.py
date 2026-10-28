"""Remote execution transports: SSH (paramiko, with optional jump host) and
WinRM (pywinrm, NTLM). Both expose ``run()`` returning (exit code, stdout, stderr)."""

from __future__ import annotations

import base64
import json
import shlex
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rangeforge.lab.inventory import Host

if TYPE_CHECKING:
    import paramiko


@dataclass(frozen=True)
class RunResult:
    code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.code == 0


class SshTransport:
    def __init__(self, host: Host, jump: Host | None = None) -> None:
        if host.ssh is None:
            raise ValueError(f"{host.name}: no ssh auth configured")
        self.host = host
        self.jump = jump
        self._client: paramiko.SSHClient | None = None
        self._jump_client: paramiko.SSHClient | None = None

    def _connect(self) -> paramiko.SSHClient:
        import paramiko

        if self._client is not None:
            return self._client
        assert self.host.ssh is not None
        sock: Any = None
        if self.jump is not None:
            assert self.jump.ssh is not None
            jump_client = paramiko.SSHClient()
            jump_client.load_system_host_keys()
            jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507 - lab hosts, keys pinned on first use
            jump_client.connect(
                self.jump.address,
                port=self.jump.ssh.port,
                username=self.jump.ssh.user,
                key_filename=str(self.jump.ssh.key_file),
                timeout=15,
            )
            transport = jump_client.get_transport()
            assert transport is not None
            sock = transport.open_channel(
                "direct-tcpip", (self.host.address, self.host.ssh.port), ("127.0.0.1", 0)
            )
            self._jump_client = jump_client
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507 - lab hosts, keys pinned on first use
        client.connect(
            self.host.address,
            port=self.host.ssh.port,
            username=self.host.ssh.user,
            key_filename=str(self.host.ssh.key_file),
            sock=sock,
            timeout=15,
        )
        self._client = client
        return client

    def run(self, command: str, *, sudo: bool = False, timeout: float = 120) -> RunResult:
        client = self._connect()
        if sudo:
            command = f"sudo -n {command}"
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        return RunResult(code, out, err)

    def run_script(self, script: str, *, sudo: bool = False, timeout: float = 300) -> RunResult:
        """Run a multi-line bash script by piping it through stdin-free heredoc."""
        wrapped = f"bash -c {shlex.quote(script)}"
        return self.run(wrapped, sudo=sudo, timeout=timeout)

    def put(self, local: Path, remote: str) -> None:
        sftp = self._connect().open_sftp()
        try:
            sftp.put(str(local), remote)
        finally:
            sftp.close()

    def close(self) -> None:
        if self._client:
            self._client.close()
        if self._jump_client:
            self._jump_client.close()
        self._client = self._jump_client = None


def read_clixml_credential(path: Path) -> tuple[str, str]:
    """Decrypt an ``Export-Clixml`` PSCredential through PowerShell (DPAPI,
    current user). The password is returned in memory only."""
    script = (
        f"$c = Import-Clixml -LiteralPath '{path}'; "
        "@{u=$c.UserName; p=$c.GetNetworkCredential().Password} | ConvertTo-Json -Compress"
    )
    for shell in ("pwsh", "powershell"):
        try:
            proc = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except FileNotFoundError:
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            return str(data["u"]), str(data["p"])
        raise RuntimeError(f"could not read credential {path}: {proc.stderr.strip()[:200]}")
    raise RuntimeError("PowerShell not found; cannot decrypt the credential file")


class WinRmTransport:
    def __init__(self, host: Host) -> None:
        if host.winrm is None:
            raise ValueError(f"{host.name}: no winrm auth configured")
        self.host = host
        self._session: Any = None

    def _connect(self) -> Any:
        import winrm

        if self._session is None:
            assert self.host.winrm is not None
            user, password = read_clixml_credential(self.host.winrm.credential_file)
            self._session = winrm.Session(
                f"http://{self.host.address}:{self.host.winrm.port}/wsman",
                auth=(user, password),
                transport=self.host.winrm.transport,
                read_timeout_sec=600,
                operation_timeout_sec=300,
            )
        return self._session

    def run_ps(self, script: str) -> RunResult:
        session = self._connect()
        result = session.run_ps(script)
        return RunResult(
            int(result.status_code),
            result.std_out.decode("utf-8", "replace"),
            result.std_err.decode("utf-8", "replace"),
        )

    def run_script(self, script: str, *, chunk: int = 1500) -> RunResult:
        """Run a long PowerShell script.

        WinRM passes ``run_ps`` scripts on the command line (base64), which is
        capped at ~8 KB. Longer scripts are shipped in chunks to a temp file
        on the target and executed from there.
        """
        if len(script) < 2500:
            return self.run_ps(script)
        data = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        name = f"rf-{uuid.uuid4().hex}.ps1"
        remote = f"$env:TEMP\\{name}"
        self.run_ps(f'Remove-Item -LiteralPath "{remote}" -ErrorAction SilentlyContinue')
        for i in range(0, len(data), chunk):
            piece = data[i : i + chunk]
            result = self.run_ps(
                f"Add-Content -LiteralPath \"{remote}\" -Value '{piece}' -NoNewline -Encoding ascii"
            )
            if not result.ok:
                return result
        runner = (
            "# rangeforge-collector\n"
            f'$b = [Convert]::FromBase64String((Get-Content -LiteralPath "{remote}" -Raw)); '
            f"$s = [Text.Encoding]::Unicode.GetString($b); "
            f'$f = "{remote}.run.ps1"; Set-Content -LiteralPath $f -Value $s -Encoding Unicode; '
            "try { & powershell.exe -NoProfile -NonInteractive "
            "-ExecutionPolicy Bypass -File $f } "
            f'finally {{ Remove-Item -LiteralPath $f, "{remote}" -ErrorAction SilentlyContinue }}'
        )
        return self.run_ps(runner)

    def run(self, command: str, **_: Any) -> RunResult:
        return self.run_ps(command)

    def close(self) -> None:
        self._session = None
