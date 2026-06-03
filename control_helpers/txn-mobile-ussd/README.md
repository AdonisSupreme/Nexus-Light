# txn-mobile-ussd ATE control helper

These scripts are the least-privilege execution layer for Nexus START, STOP, and RESTART on the ATE Mobile Banking USSD service.

The Nexus light agent should keep running as the non-root `ashumba` user. Linux will not allow that user to kill a Java process owned by another OS user, so Nexus calls these root-owned scripts through a narrow `sudo -n` allowlist.

Install target on ATE:

```text
/opt/sentinel-nexus-control/txn-mobile-ussd/start.sh
/opt/sentinel-nexus-control/txn-mobile-ussd/stop.sh
/opt/sentinel-nexus-control/txn-mobile-ussd/restart.sh
```

Required sudoers rule:

```text
ashumba ALL=(root) NOPASSWD: /opt/sentinel-nexus-control/txn-mobile-ussd/start.sh, /opt/sentinel-nexus-control/txn-mobile-ussd/stop.sh, /opt/sentinel-nexus-control/txn-mobile-ussd/restart.sh
```

The agent config should call these exact scripts via `sudo -n`, not arbitrary shell commands.

Required service control fields in `/etc/nexus-light/txn-mobile-ussd.json`:

```json
"jar_path": "/srv/afc/txn-mobile/txn-mobile-ussd/lib/txn-mobile-ussd-0.0.1-SNAPSHOT.jar",
"config_path": "/srv/afc/txn-mobile/txn-mobile-ussd/etc/application.yml",
"java_bin": "java",
"working_dir": "/srv",
"readiness_host": "127.0.0.1",
"readiness_port": 8091,
"start_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-mobile-ussd/start.sh"],
"stop_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-mobile-ussd/stop.sh"],
"restart_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-mobile-ussd/restart.sh"],
"restart_settle_seconds": 90
```

The ATE manual script starts USSD from `/srv` using:

```text
nohup java -jar /srv/afc/txn-mobile/txn-mobile-ussd/lib/txn-mobile-ussd-0.0.1-SNAPSHOT.jar --spring.config.location=/srv/afc/txn-mobile/txn-mobile-ussd/etc/application.yml &
```

The Nexus helper intentionally mirrors that launch directory. Do not change it to the jar `lib` directory; logs from ATE show that this changes the runtime shape.

Fast deploy or refresh on ATE:

```bash
sudo install -d -o root -g root -m 0750 /opt/sentinel-nexus-control/txn-mobile-ussd
sudo install -o root -g root -m 0750 start.sh /opt/sentinel-nexus-control/txn-mobile-ussd/start.sh
sudo install -o root -g root -m 0750 stop.sh /opt/sentinel-nexus-control/txn-mobile-ussd/stop.sh
sudo install -o root -g root -m 0750 restart.sh /opt/sentinel-nexus-control/txn-mobile-ussd/restart.sh
sudo visudo -c
```

ATE validation after deployment:

```bash
sudo -n /opt/sentinel-nexus-control/txn-mobile-ussd/stop.sh
sudo -n /opt/sentinel-nexus-control/txn-mobile-ussd/start.sh
pid="$(pgrep -f 'txn-mobile-ussd-0.0.1-SNAPSHOT.jar' | head -n 1)"
readlink -f "/proc/${pid}/cwd"
ss -ltnp | grep ':8091'
tail -n 80 /srv/log/ate/txn-mobile/txn-mobile-ussd/txn-mobile-ussd-human.log
```

Expected validation:

```text
/srv
Tomcat started on port(s): 8091
NotificationService - Poll Started
```
