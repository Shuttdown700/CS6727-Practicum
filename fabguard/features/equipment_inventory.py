"""
features/equipment_inventory.py -- Equipment Configuration Inventory  [FEATURE 4]

Records what fabrication equipment is on the network, what firmware it runs,
and how it is configured -- over time, so the question "what changed and
when" has an answer. Makerspaces currently have no way to audit this.

TWO SOURCES
  1. Configured machines in config.PRINTERS are queried directly for firmware,
     serial, hostname and nozzle. This is the authoritative part.
  2. An optional TCP sweep of config.INVENTORY_SUBNETS finds responsive hosts
     that are NOT configured machines. An unexpected host on the fabrication
     segment is worth a look; it may be a printer nobody declared.

Configuration is stored append-only: a new equipment_config row is written
only when the configuration hash changes, so the table is a history of
changes rather than a log of identical polls. A firmware version moving
without a corresponding change record is the thing this makes visible.

WHY TCP CONNECT RATHER THAN PING
    ICMP needs raw sockets or a sysctl change; a TCP connect to a small port
    list needs neither and runs unprivileged on the Pi. It finds fewer hosts
    (a device with every port closed is invisible) and that limitation is
    worth stating rather than implying the sweep is exhaustive.

    Keep INVENTORY_SUBNETS pointed at the lab segment.

Standalone:
    python3 -m fabguard.features.equipment_inventory
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor

from .. import adapters, config
from ..core import db
from ..core.registry import Feature, FeatureResult, standalone


class EquipmentConfigurationInventory(Feature):
    name = "equipment_inventory"
    title = "Equipment Configuration Inventory"
    description = ("Records fabrication equipment present on the network, firmware "
                   "in use, and network configuration over time.")

    def collect(self) -> FeatureResult:
        counts = {"configured": 0, "reachable": 0, "config_changes": 0,
                  "swept_hosts": 0, "undeclared": 0, "absent": 0}
        detail = {}
        arp = self._arp_table()
        seen_ips = set()

        # -- declared machines --------------------------------------------
        for printer in adapters.all_printers():
            counts["configured"] += 1
            host = getattr(printer, "host", None)
            try:
                ident = printer.identity()
            except Exception as exc:
                ident = {"printer_id": printer.id, "host": host, "error": str(exc)}

            # identity() reports per-endpoint failures in the dict rather than
            # raising, so that one dead endpoint still yields what the other
            # returned. A machine only counts as reachable when at least one
            # probe produced something -- otherwise an unplugged printer would
            # be inventoried as present with every field null, which is worse
            # than recording it as absent.
            errs = [k for k in ("error", "version_error", "info_error") if ident.get(k)]
            got_anything = any(ident.get(k) for k in
                               ("firmware", "api_version", "serial", "name", "hostname"))
            reachable = got_anything and "error" not in errs
            if reachable:
                counts["reachable"] += 1
            if errs:
                self.finding("WARNING", "equipment.inventory_failed", printer.id,
                             f"Could not fully read configuration from {printer.label}"
                             + ("" if got_anything else " (no response at all)"),
                             {"errors": {k: ident[k] for k in errs}, "host": host,
                              "partial": got_anything},
                             dedup_key=f"inv-failed:{printer.id}:{'partial' if got_anything else 'total'}")

            ip = host or f"sim:{printer.id}"
            seen_ips.add(ip)
            ports = self._probe_ports(host) if (reachable and host and
                                                not str(host).startswith("sim")) else []
            eq_id = self._upsert_equipment(ip, arp.get(ip), ident.get("hostname"),
                                           printer.id, "PRINTER", present=reachable)
            if reachable and self._record_config(eq_id, ident, ports):
                counts["config_changes"] += 1
            detail[printer.id] = {"host": host, "reachable": reachable,
                                  "firmware": ident.get("firmware"),
                                  "serial": ident.get("serial"),
                                  "open_ports": ports}

        # -- sweep ---------------------------------------------------------
        if config.INVENTORY_ENABLE_SWEEP:
            found = self._sweep()
            counts["swept_hosts"] = len(found)
            declared = {getattr(p, "host", None) for p in adapters.all_printers()}
            for ip, ports in found.items():
                seen_ips.add(ip)
                if ip in declared:
                    continue
                counts["undeclared"] += 1
                eq_id = self._upsert_equipment(ip, arp.get(ip), self._rdns(ip),
                                               None, "UNKNOWN_HOST", present=True)
                self._record_config(eq_id, {"host": ip}, ports)
                self.finding(
                    "NOTICE", "equipment.undeclared", ip,
                    f"Host {ip} answers on the fabrication segment but is not in "
                    f"config.PRINTERS",
                    {"open_ports": ports, "mac": arp.get(ip),
                     "hostname": self._rdns(ip),
                     "note": "Either declare it or find out what it is."},
                    dedup_key=f"undeclared:{ip}")

        counts["absent"] = self._mark_absent(seen_ips)

        summary = (f"{counts['reachable']}/{counts['configured']} machine(s) reachable, "
                   f"{counts['config_changes']} config change(s), "
                   f"{counts['undeclared']} undeclared host(s)")
        return FeatureResult(summary, counts,
                             counts["undeclared"] + (counts["configured"] - counts["reachable"]),
                             detail)

    # -- equipment rows ----------------------------------------------------

    def _upsert_equipment(self, ip: str, mac: str | None, hostname: str | None,
                          printer_id: str | None, kind: str, present: bool) -> int:
        now = db.now()
        with db.tx() as c:
            c.execute(
                "INSERT INTO equipment(ip, mac, hostname, printer_id, kind,"
                " first_seen_ts, last_seen_ts, present) VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(ip) DO UPDATE SET"
                "   mac=COALESCE(excluded.mac, mac),"
                "   hostname=COALESCE(excluded.hostname, hostname),"
                "   printer_id=COALESCE(excluded.printer_id, printer_id),"
                "   kind=excluded.kind, last_seen_ts=excluded.last_seen_ts,"
                "   present=excluded.present",
                (ip, mac, hostname, printer_id, kind, now, now, 1 if present else 0))
        return db.q1("SELECT id FROM equipment WHERE ip=?", (ip,))["id"]

    def _record_config(self, equipment_id: int, ident: dict, ports: list[int]) -> bool:
        """
        Write a config row only when something changed. Returns True if it did.

        The hash covers the fields that matter for the compliance question --
        firmware, serial, nozzle, open ports -- and deliberately not the
        volatile ones, so a temperature reading does not look like a
        configuration change.
        """
        material = {
            "firmware": ident.get("firmware"),
            "api_version": ident.get("api_version"),
            "serial": ident.get("serial"),
            "nozzle": ident.get("nozzle"),
            "hostname": ident.get("hostname"),
            "ports": sorted(ports),
        }
        chash = hashlib.sha256(db.jdump(material).encode()).hexdigest()
        last = db.q1("SELECT * FROM equipment_config WHERE equipment_id=?"
                     " ORDER BY id DESC LIMIT 1", (equipment_id,))
        if last and last["config_hash"] == chash:
            return False

        with db.tx() as c:
            c.execute(
                "INSERT INTO equipment_config"
                "(equipment_id, ts, firmware, api_version, serial, nozzle,"
                " open_ports, raw, config_hash) VALUES (?,?,?,?,?,?,?,?,?)",
                (equipment_id, db.now(), material["firmware"], material["api_version"],
                 material["serial"], str(material["nozzle"]),
                 db.jdump(material["ports"]), db.jdump(ident), chash))

        if last:
            before = {"firmware": last["firmware"], "serial": last["serial"],
                      "nozzle": last["nozzle"], "ports": last["open_ports"]}
            after = {"firmware": material["firmware"], "serial": material["serial"],
                     "nozzle": str(material["nozzle"]),
                     "ports": db.jdump(material["ports"])}
            delta = {k: [before[k], after[k]] for k in after if before.get(k) != after[k]}
            self.emit("equipment.config.changed", subject=str(equipment_id),
                      data={"changes": delta})
            sev = "WARNING" if "firmware" in delta else "NOTICE"
            self.finding(
                sev, "equipment.config_changed", ident.get("printer_id") or str(equipment_id),
                f"Configuration changed on {ident.get('name') or ident.get('host')}: "
                f"{', '.join(delta)}",
                {"changes": delta},
                dedup_key=f"cfgchange:{equipment_id}:{chash}")
        else:
            self.emit("equipment.config.baseline", subject=str(equipment_id),
                      data=material)
        return True

    def _mark_absent(self, seen: set) -> int:
        rows = db.q("SELECT * FROM equipment WHERE present=1")
        gone = [r for r in rows if r["ip"] not in seen]
        for r in gone:
            with db.tx() as c:
                c.execute("UPDATE equipment SET present=0 WHERE id=?", (r["id"],))
            self.emit("equipment.absent", subject=r["ip"],
                      data={"printer_id": r["printer_id"], "kind": r["kind"],
                            "last_seen_ts": r["last_seen_ts"]})
        return len(gone)

    # -- network -----------------------------------------------------------

    def _probe_ports(self, host: str) -> list[int]:
        open_ports = []
        for port in config.INVENTORY_PROBE_PORTS:
            if self._tcp_open(host, port):
                open_ports.append(port)
        return open_ports

    @staticmethod
    def _tcp_open(host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port),
                                          timeout=config.INVENTORY_PROBE_TIMEOUT_S):
                return True
        except Exception:
            return False

    def _sweep(self) -> dict[str, list[int]]:
        """TCP-connect sweep of the configured subnets. Unprivileged, partial."""
        targets = []
        for cidr in config.INVENTORY_SUBNETS:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                self.finding("WARNING", "inventory.bad_subnet", cidr,
                             f"config.INVENTORY_SUBNETS contains an unparseable value: {cidr}",
                             {}, dedup_key=f"bad-subnet:{cidr}")
                continue
            if net.num_addresses > 1024:
                self.finding("NOTICE", "inventory.subnet_too_large", cidr,
                             f"Skipping {cidr}: {net.num_addresses} addresses is too "
                             f"many to sweep on a polling interval",
                             {"num_addresses": net.num_addresses},
                             dedup_key=f"subnet-large:{cidr}")
                continue
            targets.extend(str(h) for h in net.hosts())

        found: dict[str, list[int]] = {}

        def probe(ip: str):
            ports = [p for p in config.INVENTORY_PROBE_PORTS if self._tcp_open(ip, p)]
            return ip, ports

        with ThreadPoolExecutor(max_workers=config.INVENTORY_MAX_WORKERS) as pool:
            for ip, ports in pool.map(probe, targets):
                if ports:
                    found[ip] = ports
        return found

    @staticmethod
    def _arp_table() -> dict[str, str]:
        """
        IP -> MAC from the kernel ARP cache. Hardware identity survives a DHCP
        lease change, which an IP does not, so it is worth recording.
        Only populated for hosts recently talked to.
        """
        out = {}
        try:
            with open("/proc/net/arp", "r") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 4 and re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$",
                                                    parts[3], re.I):
                        if parts[3] != "00:00:00:00:00:00":
                            out[parts[0]] = parts[3].lower()
        except Exception:
            pass
        return out

    @staticmethod
    def _rdns(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None


if __name__ == "__main__":
    standalone(EquipmentConfigurationInventory)
