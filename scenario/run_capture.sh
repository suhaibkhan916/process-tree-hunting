#!/bin/bash
# Runs inside the sensor container: start rsyslog and Sysmon, start the web app,
# play the workload (benign only, or benign plus attack), copy the events to /out.
set -u
name="$1"      # baseline or incident
mount -t debugfs none /sys/kernel/debug
mount -t tracefs none /sys/kernel/tracing
rsyslogd
sleep 1
sysmon -accepteula -i /configs/sysmon-process.xml > /dev/null 2>&1
/opt/sysmon/sysmon -i /opt/sysmon/config.xml -service > /tmp/sysmon-service.log 2>&1 &
for _ in $(seq 1 30); do
  grep -q "<EventID>4</EventID>" /var/log/syslog && break
  sleep 1
done
grep -q "<EventID>4</EventID>" /var/log/syslog || { cat /tmp/sysmon-service.log; exit 1; }

python3 /lab/scenario/webapp.py &
sleep 2
bash /lab/scenario/benign.sh 12 &
benign=$!
if [ "$name" = "incident" ]; then
  sleep 4
  bash /lab/scenario/attack.sh
fi
wait "$benign"
sleep 3
grep "sysmon: <Event>" /var/log/syslog > "/tmp/$name.log"
echo "$name: $(wc -l < "/tmp/$name.log") events"
cp "/tmp/$name.log" /out/
