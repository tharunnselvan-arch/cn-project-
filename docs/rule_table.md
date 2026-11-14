# Detection rule table

| Rule | Default threshold | Window | Action |
|---|---:|---:|---|
| TCP port scan | 8 distinct destination ports | 10 seconds | Drop all IPv4 traffic from source for 60 seconds |
| TCP connection burst | 25 initial SYN packets | 5 seconds | Drop all IPv4 traffic from source for 60 seconds |

Thresholds are demonstration defaults, not universal definitions of malicious activity.
Tune them in `config/rules.json`. The controller counts observed TCP SYN packet-ins by source.
