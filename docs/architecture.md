# Architecture

```mermaid
flowchart LR
  H1[h1 normal client] --> S1[OVS s1]
  H2[h2 normal client] --> S1
  H3[h3 normal client] --> S1
  H4[h4 controlled attacker] --> S1
  S1 --> H5[h5 concurrent TCP server]
  S1 <-->|OpenFlow 1.3 / Packet-In / Flow-Mod / Stats| C[OS-Ken SDN controller]
  C --> D[Detection module: scan + SYN-rate rules]
  D --> L[CSV event and statistics logs]
```

The controller observes packets using a table-miss rule and forwards non-blocked traffic
with Packet-Out. On a rule match it installs a higher-priority IPv4-source drop rule with
a hard timeout. The application uses Python's standard `socket` module.
