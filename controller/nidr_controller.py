#!/usr/bin/env python3
"""
NIDR controller application for OS-Ken / OpenFlow 1.3.

All non-blocked packets are sent through the controller (table-miss + packet-out).
This makes packet-in observation deterministic for this small teaching topology.
The controller tracks TCP SYN attempts per source, polls switch flow/port statistics,
and installs a higher-priority IPv4-source drop rule on detection.
"""
import csv
import json
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet, ipv4, tcp


class NIDRController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        config_path = os.environ.get("NIDR_CONFIG", "config/rules.json")
        with open(config_path, "r", encoding="utf-8") as f:
            self.cfg = json.load(f)

        self.scan_events = defaultdict(deque)       # src -> (timestamp, dst_port)
        self.syn_events = defaultdict(deque)        # src -> timestamps
        self.packet_in_counts = defaultdict(int)    # source -> packet-in count
        self.first_seen = {}
        self.blocked_until = {}
        self.datapaths = {}
        self.started_at = time.time()
        self.last_alert_at = {}
        self.log_dir = self.cfg.get("log_directory", "results")
        os.makedirs(self.log_dir, exist_ok=True)
        self.events_path = os.path.join(self.log_dir, "events.csv")
        self.stats_path = os.path.join(self.log_dir, "switch_stats.csv")
        self._init_csv(self.events_path,
                       ["timestamp_utc", "event", "source_ip", "rule",
                        "observed_rate", "detection_time_ms", "response_time_ms",
                        "block_seconds"])
        self._init_csv(self.stats_path,
                       ["timestamp_utc", "datapath_id", "stat_type",
                        "port_or_table", "packets", "bytes", "flows",
                        "source_ip", "packet_in_count"])

        self.logger.info("NIDR controller started; config=%s", config_path)
        self.stats_thread = hub.spawn(self._poll_switch_stats)

    @staticmethod
    def _init_csv(path, header):
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            with open(path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(header)

    def _csv(self, path, row):
        with open(path, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)

    @staticmethod
    def _now_iso():
        return datetime.now(timezone.utc).isoformat()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        # Priority 0 table-miss: send packets to controller.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0,
                                      match=match, instructions=inst))
        self.logger.info("Switch %s connected to NIDR controller", dp.id)

    def _install_drop(self, dp, src_ip):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        # hard_timeout ensures expiry even if attack packets continue.
        msg = parser.OFPFlowMod(
            datapath=dp, priority=200, match=match,
            instructions=[], hard_timeout=int(self.cfg["block_seconds"]),
            idle_timeout=0,
            flags=ofp.OFPFF_SEND_FLOW_REM)
        start = time.perf_counter()
        dp.send_msg(msg)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.blocked_until[src_ip] = time.time() + int(self.cfg["block_seconds"])
        return elapsed_ms

    def _alert_and_block(self, dp, src_ip, rule, rate, detection_ms):
        now = time.time()
        if src_ip in self.blocked_until and self.blocked_until[src_ip] > now:
            return
        block_seconds = int(self.cfg["block_seconds"])
        self.logger.warning("[ALERT] %s source=%s observed=%s",
                            rule, src_ip, rate)
        response_ms = self._install_drop(dp, src_ip)
        self.logger.warning("[BLOCKED] source=%s duration=%ss",
                            src_ip, block_seconds)
        self._csv(self.events_path, [
            self._now_iso(), "BLOCK", src_ip, rule, rate,
            round(detection_ms, 3), round(response_ms, 3), block_seconds
        ])

    def _check_detection(self, dp, src_ip, dst_port, now):
        # Port scan: N distinct destination ports inside T seconds.
        scan_q = self.scan_events[src_ip]
        scan_q.append((now, dst_port))
        scan_window = float(self.cfg["scan_window_seconds"])
        while scan_q and now - scan_q[0][0] > scan_window:
            scan_q.popleft()
        unique_ports = len({p for _, p in scan_q})
        scan_threshold = int(self.cfg["scan_unique_ports_threshold"])
        if unique_ports >= scan_threshold:
            first = scan_q[0][0]
            self._alert_and_block(
                dp, src_ip, "PORT_SCAN",
                f"{unique_ports} unique ports/{scan_window:g}s",
                (now - first) * 1000.0)
            return

        # Rapid connection burst: N TCP SYNs inside T seconds.
        syn_q = self.syn_events[src_ip]
        syn_q.append(now)
        burst_window = float(self.cfg["burst_window_seconds"])
        while syn_q and now - syn_q[0] > burst_window:
            syn_q.popleft()
        burst_threshold = int(self.cfg["burst_syn_threshold"])
        if len(syn_q) >= burst_threshold:
            first = syn_q[0]
            self._alert_and_block(
                dp, src_ip, "TCP_CONNECTION_BURST",
                f"{len(syn_q)} SYNs/{burst_window:g}s",
                (now - first) * 1000.0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip4 = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ip4:
            self.packet_in_counts[ip4.src] += 1

        if ip4 and tcp_pkt:
            syn = bool(tcp_pkt.bits & 0x02)
            ack = bool(tcp_pkt.bits & 0x10)
            if syn and not ack:
                self._check_detection(dp, ip4.src, tcp_pkt.dst_port, time.time())

        # Forward by flooding within this single-switch lab. A source drop
        # flow, when present, has higher priority and prevents packet-ins.
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        data = None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=msg.match["in_port"], actions=actions, data=data)
        dp.send_msg(out)

    def _poll_switch_stats(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp))
                dp.send_msg(parser.OFPPortStatsRequest(dp, 0xFFFFFFFF, 0xFFFFFFFF))
            hub.sleep(float(self.cfg.get("stats_poll_seconds", 5)))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply(self, ev):
        dp = ev.msg.datapath
        total_packets = sum(x.packet_count for x in ev.msg.body)
        total_bytes = sum(x.byte_count for x in ev.msg.body)
        self._csv(self.stats_path, [
            self._now_iso(), dp.id, "FLOW", "all",
            total_packets, total_bytes, len(ev.msg.body), "", ""
        ])

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply(self, ev):
        dp = ev.msg.datapath
        for stat in ev.msg.body:
            self._csv(self.stats_path, [
                self._now_iso(), dp.id, "PORT", stat.port_no,
                stat.rx_packets + stat.tx_packets,
                stat.rx_bytes + stat.tx_bytes, "", "", ""
            ])
        # Per-source packet-in counts are controller-observed source metrics.
        for src, count in list(self.packet_in_counts.items()):
            self._csv(self.stats_path, [
                self._now_iso(), dp.id, "PACKET_IN_SOURCE", "",
                "", "", "", src, count
            ])

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed(self, ev):
        msg = ev.msg
        match = msg.match
        src_ip = match.get("ipv4_src")
        if src_ip:
            self.blocked_until.pop(src_ip, None)
            self.logger.info("[UNBLOCKED] timed drop rule expired for %s", src_ip)
            self._csv(self.events_path, [
                self._now_iso(), "UNBLOCK", src_ip, "HARD_TIMEOUT",
                "", "", "", self.cfg["block_seconds"]
            ])
