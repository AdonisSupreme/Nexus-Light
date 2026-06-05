# txn-ussd-adapter ATE control helper

These scripts are the least-privilege execution layer for Nexus START, STOP, and RESTART on the ATE USSD Adapter service.

Install target on ATE:

```text
/opt/sentinel-nexus-control/txn-ussd-adapter/start.sh
/opt/sentinel-nexus-control/txn-ussd-adapter/stop.sh
/opt/sentinel-nexus-control/txn-ussd-adapter/restart.sh
```

Required sudoers rule:

```text
ashumba ALL=(root) NOPASSWD: /opt/sentinel-nexus-control/txn-ussd-adapter/start.sh, /opt/sentinel-nexus-control/txn-ussd-adapter/stop.sh, /opt/sentinel-nexus-control/txn-ussd-adapter/restart.sh
```

The helper mirrors the ATE manual control script from `/srv/main.sh`:

```text
nohup java -jar /srv/afc/txn-mobile/txn-ussd-adapter/lib/txn-ussd-adapter-0.0.1-SNAPSHOT.jar --spring.config.location=/srv/afc/txn-mobile/txn-ussd-adapter/etc/application.yml &
```

When invoked by the light agent, `start.sh` delegates Java to the transient systemd unit `sentinel-nexus-txn-ussd-adapter.service`. This prevents the adapter JVM from inheriting the Nexus light-agent cgroup resource limits.

Required service control fields in `/etc/nexus-light/txn-mobile-ussd.json`:

```json
"jar_path": "/srv/afc/txn-mobile/txn-ussd-adapter/lib/txn-ussd-adapter-0.0.1-SNAPSHOT.jar",
"config_path": "/srv/afc/txn-mobile/txn-ussd-adapter/etc/application.yml",
"java_bin": "java",
"working_dir": "/srv",
"readiness_host": "127.0.0.1",
"readiness_port": null,
"start_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-ussd-adapter/start.sh"],
"stop_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-ussd-adapter/stop.sh"],
"restart_command": ["sudo", "-n", "/opt/sentinel-nexus-control/txn-ussd-adapter/restart.sh"],
"restart_settle_seconds": 30
```

`readiness_port` is intentionally `null` until the ATE adapter `application.yml` is inspected on the host. The light agent will discover `server.port` from `config_path` at runtime. If the command below returns a concrete port, store that exact value in the local config and in the Nexus service metadata:

```bash
grep -nE '^[[:space:]]*server:|^[[:space:]]*port:' /srv/afc/txn-mobile/txn-ussd-adapter/etc/application.yml
```

ATE validation after deployment:

```bash
sudo -n /opt/sentinel-nexus-control/txn-ussd-adapter/stop.sh
sudo -n /opt/sentinel-nexus-control/txn-ussd-adapter/start.sh
pid="$(pgrep -f 'txn-ussd-adapter-0.0.1-SNAPSHOT.jar' | head -n 1)"
readlink -f "/proc/${pid}/cwd"
systemctl status sentinel-nexus-txn-ussd-adapter.service --no-pager -l
ss -ltnp | grep java
tail -n 80 /srv/log/ate/txn-mobile/txn-ussd-adapter/txn-ussd-adapter-human.log
```

Expected validation:

```text
/srv
Active: active
The adapter process is visible and, if server.port is declared, the declared port is listening.
```
