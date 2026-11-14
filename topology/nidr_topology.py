#!/usr/bin/env python3
"""Team 2 NIDR topology: h1-h3 normal clients, h4 attacker, h5 TCP server."""
from mininet.topo import Topo

class NIDRTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        for name, ip in [
            ("h1", "10.0.0.1/24"),
            ("h2", "10.0.0.2/24"),
            ("h3", "10.0.0.3/24"),
            ("h4", "10.0.0.4/24"),
            ("h5", "10.0.0.5/24"),
        ]:
            host = self.addHost(name, ip=ip)
            self.addLink(host, s1)

topos = {"nidr": lambda: NIDRTopo()}
