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
