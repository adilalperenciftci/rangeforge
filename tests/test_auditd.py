from datetime import UTC, datetime

from rangeforge.ingest.auditd import iter_audit_lines, parse_record
from rangeforge.schema.events import EventClass

RAW = """type=SYSCALL msg=audit(1793170341.250:3774): arch=c000003e syscall=59 success=yes exit=0 a0=60f04a24d278 a1=60f04a251f80 a2=60f04a26b8b0 a3=64 items=2 ppid=27510 pid=27514 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=12 comm="tail" exe="/usr/bin/tail" subj=unconfined key="exec"
type=EXECVE msg=audit(1793170341.250:3774): argc=4 a0="tail" a1="-n" a2="400" a3="/var/log/audit/audit.log"
type=CWD msg=audit(1793170341.250:3774): cwd="/home/bluexadmin"
type=PATH msg=audit(1793170341.250:3774): item=0 name="/usr/bin/tail" inode=1961 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1793170341.250:3774): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=6459 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PROCTITLE msg=audit(1793170341.250:3774): proctitle=7461696C002D6E00343030002F7661722F6C6F672F61756469742F61756469742E6C6F67
type=SYSCALL msg=audit(1793170342.000:3775): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c items=1 ppid=1 pid=99 auid=1000 uid=1000 comm="vim" exe="/usr/bin/vim" key="identity"
type=PATH msg=audit(1793170342.000:3775): item=0 name="/etc/passwd" inode=1 dev=08:01 mode=0100644 ouid=0 ogid=0 nametype=NORMAL
type=USER_LOGIN msg=audit(1793170343.000:3776): pid=5 uid=0 auid=1000 ses=13 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=172.28.10.1 addr=172.28.10.1 terminal=/dev/pts/1 res=success'
"""


def test_parse_record_handles_quotes_and_hex() -> None:
    parsed = parse_record(RAW.splitlines()[5])
    assert parsed is not None
    rtype, ts, serial, fields = parsed
    assert (rtype, ts, serial) == ("PROCTITLE", "1793170341.250", 3774)
    assert fields["proctitle"] == "tail -n 400 /var/log/audit/audit.log"


def test_groups_and_classifies() -> None:
    events = list(iter_audit_lines(RAW.splitlines(), hostname="bluex-ubuntu"))
    assert [e.metadata.original_event_id for e in events] == ["SYSCALL", "SYSCALL", "USER_LOGIN"]

    execve = events[0]
    assert execve.class_uid is EventClass.PROCESS_ACTIVITY
    assert execve.time == datetime.fromtimestamp(1793170341.250, tz=UTC)
    assert execve.native["Image"] == "/usr/bin/tail"
    assert execve.native["CommandLine"] == "tail -n 400 /var/log/audit/audit.log"
    assert execve.native["key"] == "exec"
    assert execve.native["syscall_name"] == "execve"
    assert execve.native["cwd"] == "/home/bluexadmin"
    assert execve.native["name"] == "/usr/bin/tail"
    assert execve.process is not None and execve.process.pid == 27514
    assert execve.process.parent is not None and execve.process.parent.pid == 27510
    assert execve.device.hostname == "bluex-ubuntu"
    assert execve.metadata.uid == "1793170341.250:3774"

    file_access = events[1]
    assert file_access.class_uid is EventClass.FILE_ACTIVITY
    assert file_access.file is not None and file_access.file.path == "/etc/passwd"
    assert file_access.native["key"] == "identity"

    login = events[2]
    assert login.class_uid is EventClass.AUTHENTICATION
    assert login.native["type"] == "USER_LOGIN"
