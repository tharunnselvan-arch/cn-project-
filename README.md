# Network Intrusion Detection and Response (TCP)

Team 2 mini-project: controlled TCP scan/burst detection and dynamic source blocking
inside Mininet using Open vSwitch and an OpenFlow 1.3 SDN controller.

## Components

- `topology/nidr_topology.py`: h1-h3 normal clients, h4 attacker, h5 server, one OVS switch.
- `controller/nidr_controller.py`: OS-Ken OpenFlow 1.3 controller; packet-in observation,
  source-based scan/burst detection, drop rule installation, flow/port stats polling.
- `app/tcp_server.py`: concurrent TCP server using `socket` and `threading`.
- `app/tcp_client.py`: normal TCP client using `socket`.
- `app/attacker.py`: controlled port sweep and rapid connection burst using `socket`.
- `config/rules.json`: editable thresholds and timeouts.
- `results/`: controller writes `events.csv` and `switch_stats.csv` here.
- `tests/`: repeatable test commands.

## Lab safety

Run only inside the private Mininet topology created by this project. The attacker script
defaults to the Mininet server address `10.0.0.5`; do not point it at public or third-party
systems.

## Requirements

Ubuntu VM with Python 3, Mininet, Open vSwitch, and an OpenFlow 1.3 capable switch.
This repository uses OS-Ken (Ryu-derived) as the controller API. If your instructor
requires the Ryu or POX executable specifically, confirm OS-Ken is acceptable before
submission; do not label OS-Ken as Ryu.

Install OS-Ken in a virtual environment (tested project target: `os-ken==3.1.1`):

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-venv python3-pip
cd ~/NIDR
python3 -m venv osken-env
source osken-env/bin/activate
python -m pip install --upgrade pip
pip install "os-ken==3.1.1"
```

## Start the demo

Open two Ubuntu terminal windows.

### Terminal 1 — controller

From the repository root:

```bash
cd ~/NIDR
source osken-env/bin/activate
osken-manager controller/nidr_controller.py
```

Keep this terminal open. Wait for `NIDR controller started` and
`Switch 1 connected to NIDR controller`.

### Terminal 2 — Mininet

```bash
cd ~/NIDR
sudo mn --custom topology/nidr_topology.py --topo nidr \
  --switch ovsk,protocols=OpenFlow13 \
  --controller remote,ip=127.0.0.1,port=6653
```

At the `mininet>` prompt, start the server once:

```text
h5 python3 app/tcp_server.py &
```

Run normal clients:

```text
h1 python3 app/tcp_client.py 10.0.0.5 5000 "Hello from h1"
h2 python3 app/tcp_client.py 10.0.0.5 5000 "Hello from h2"
h3 python3 app/tcp_client.py 10.0.0.5 5000 "Hello from h3"
```

Run the controlled port scan:

```text
h4 python3 app/attacker.py scan --start-port 4995 --end-port 5005
```

Run the rapid connection burst:

```text
h4 python3 app/attacker.py burst --count 40 --interval 0.02
```

Switch to Terminal 1 to inspect alerts. The expected alert text includes
`PORT_SCAN` or `TCP_CONNECTION_BURST`, followed by a source IP.

Inspect installed switch rules from the Mininet prompt:

```text
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Look for a high-priority flow matching `ipv4_src=10.0.0.4` with no actions
(the drop rule). During the 60-second block, test h4 and a normal client:

```text
h4 python3 app/tcp_client.py 10.0.0.5 5000 "should be blocked"
h1 python3 app/tcp_client.py 10.0.0.5 5000 "normal client still works"
```

After the hard timeout expires, test h4 again:

```text
h4 python3 app/tcp_client.py 10.0.0.5 5000 "access restored"
```

## Important operational notes

- Start the TCP server only once. `Address already in use` means a server is already
  listening on port 5000; do not launch a second copy.
- If the controller terminal has no prompt, that is normal: the controller is running.
- If you need to stop Mininet, type `exit` at `mininet>`; then run `sudo mn -c`
  in a normal Ubuntu terminal if cleanup is needed.
- If h4 is blocked by a scan, wait for the configured 60-second timeout before running
  the next attack test.
- The controller uses a hard timeout, so the block expires after 60 seconds even if
  matching packets continue to arrive.

## Detection logic and limitations

The controller detects:
1. At least 8 unique TCP destination ports from one source within 10 seconds.
2. At least 25 initial TCP SYN packet-ins from one source within 5 seconds.

It counts TCP SYN packet-ins per source and writes packet-in source counts, aggregate
OpenFlow flow statistics, and port statistics to CSV. The flow/port stats are switch-wide;
the source-specific rate is derived from observed packet-ins. This is explicitly logged
rather than claiming OpenFlow flow counters are intrinsically per-source.

This teaching implementation uses one switch and Packet-Out flooding to keep all packets
observable. It is not a production firewall. The half-open-connection rule is not
implemented in this version because accurate half-open detection requires tracking TCP
handshakes and timeouts; do not claim it is implemented in the report.

## Results and evaluation

The controller creates:
- `results/events.csv`: alert/block/unblock events and timing fields.
- `results/switch_stats.csv`: aggregate flow stats, port stats, and per-source packet-in
  counts.

Run at least light, medium and heavy traffic conditions. Record actual measurements;
do not invent results. Compare:
- no detection (controller forwarding only),
- dynamic detection and blocking,
- static block (manually installed drop rule).

Measure detection time, response time, false positives/negatives, and normal-client
success/latency. A simple drop-rule baseline can be installed from the Mininet prompt:

```text
sh ovs-ofctl -O OpenFlow13 add-flow s1 "priority=200,ip,nw_src=10.0.0.4,actions=drop"
```

Remove that static rule after the baseline:

```text
sh ovs-ofctl -O OpenFlow13 del-flows s1 "priority=200,ip,nw_src=10.0.0.4"
```

## GitHub upload

From the parent directory of `NIDR`:

```bash
git init
git add .
git commit -m "Initial NIDR TCP intrusion detection project"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

Replace the remote URL with your own GitHub repository URL.
