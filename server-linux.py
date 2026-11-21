#!/usr/bin/env python3
"""
Wi-Fi RSSI Live Monitor — Cross-Platform Real Hardware Backend
Zero external dependencies (Python 3 standard library only).

Reads real Wi-Fi hardware telemetry directly from your OS:
  - Windows: wlanapi.dll (WlanQueryInterface + WlanGetNetworkBssList + 802.11 IE parser
             for true 20/40/80/160 MHz channel width, exact frequency, mode & nearby APs)
  - Linux:   iw / nmcli
  - macOS:   system_profiler SPAirPortDataType

No hardcoded router names, no fake channels, no synthetic data.
Run:  python server.py
Open: http://localhost:8000  (or http://<your-local-ip>:8000 from any phone/laptop on the same Wi-Fi)
"""

import ctypes
import http.server
import json
import os
import platform
import re
import socket
import socketserver
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8000"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Helpers: Frequency <-> Channel & Band
# ---------------------------------------------------------------------------

def freq_to_band(freq_mhz):
    if not freq_mhz:
        return None
    if 2400 <= freq_mhz <= 2500:
        return "2.4 GHz"
    if 5150 <= freq_mhz <= 5895:
        return "5 GHz"
    if 5925 <= freq_mhz <= 7125:
        return "6 GHz"
    return None


def freq_to_channel(freq_mhz):
    if not freq_mhz:
        return None
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if 5150 <= freq_mhz <= 5895:
        return (freq_mhz - 5000) // 5
    if 5955 <= freq_mhz <= 7115:
        return (freq_mhz - 5950) // 5
    return None


def channel_to_freq(ch, band_hint=None):
    if ch is None:
        return None
    if band_hint == "6 GHz":
        return 5950 + 5 * ch
    if 1 <= ch <= 13:
        return 2407 + 5 * ch
    if ch == 14:
        return 2484
    if 32 <= ch <= 177:
        return 5000 + 5 * ch
    return None


# ---------------------------------------------------------------------------
# 802.11 Beacon Information Element (IE) Parser
# Extracts real channel width (20/40/80/160 MHz), Wi-Fi mode (n/ac/ax/be),
# and security from raw Windows WLAN_BSS_ENTRY IEs — just like NetSpot.
# ---------------------------------------------------------------------------

def parse_ies(ie_bytes, freq_mhz=None):
    width_mhz = 20
    modes = set()
    has_rsn = False
    has_wpa1 = False
    is_wpa3 = False
    is_enterprise = False

    i = 0
    n = len(ie_bytes)
    while i + 2 <= n:
        eid = ie_bytes[i]
        elen = ie_bytes[i + 1]
        data = ie_bytes[i + 2 : i + 2 + elen]
        i += 2 + elen
        if len(data) < elen:
            break

        # 45: HT Capabilities (802.11n)
        if eid == 45 and len(data) >= 2:
            modes.add("n")

        # 61: HT Operation (802.11n) -> 20 vs 40 MHz
        elif eid == 61 and len(data) >= 2:
            modes.add("n")
            sec_ch_offset = data[1] & 0x03
            if sec_ch_offset in (1, 3) and width_mhz < 40:
                width_mhz = 40

        # 191: VHT Capabilities (802.11ac)
        elif eid == 191 and len(data) >= 4:
            modes.add("ac")

        # 192: VHT Operation (802.11ac) -> 80 / 160 MHz
        elif eid == 192 and len(data) >= 3:
            modes.add("ac")
            vht_w = data[0]
            ccfs0 = data[1]
            ccfs1 = data[2]
            if vht_w == 1:
                if ccfs1 != 0 and abs(ccfs1 - ccfs0) == 8:
                    width_mhz = max(width_mhz, 160)
                else:
                    width_mhz = max(width_mhz, 80)
            elif vht_w in (2, 3):
                width_mhz = max(width_mhz, 160)

        # 255: Extension IE (HE / EHT -> Wi-Fi 6 / 6E / 7)
        elif eid == 255 and len(data) >= 1:
            ext_id = data[0]
            ext_data = data[1:]
            if ext_id == 35:  # HE Capabilities
                modes.add("ax")
            elif ext_id == 36:  # HE Operation
                modes.add("ax")
                # Check 6 GHz Operation Information if present
                if len(ext_data) >= 6:
                    he_params = ext_data[0] | (ext_data[1] << 8) | (ext_data[2] << 16)
                    has_6g = (he_params >> 17) & 1
                    if has_6g:
                        # Offset after 3-byte params + 1-byte BSS color + 2-byte MCS
                        off = 6
                        if (he_params >> 14) & 1:  # VHT op info present
                            off += 3
                        if (he_params >> 15) & 1:  # Max Co-Hosted BSSID
                            off += 1
                        if len(ext_data) >= off + 2:
                            ctrl = ext_data[off + 1]
                            w_code = ctrl & 0x03
                            w_map = {0: 20, 1: 40, 2: 80, 3: 160}
                            width_mhz = max(width_mhz, w_map.get(w_code, 20))
            elif ext_id in (106, 108):  # EHT Operation / Capabilities (Wi-Fi 7)
                modes.add("be")
                if ext_id == 106 and len(ext_data) >= 2:
                    if ext_data[0] & 0x01:  # EHT Operation Info Present
                        eht_w = ext_data[1] & 0x07
                        w_map = {0: 20, 1: 40, 2: 80, 3: 160, 4: 320}
                        width_mhz = max(width_mhz, w_map.get(eht_w, 20))

        # 48: RSN IE (WPA2 / WPA3)
        elif eid == 48 and len(data) >= 8:
            has_rsn = True
            # Scan AKM suites for SAE (WPA3, OUI 00-0F-AC type 8) or 802.1X (type 1 or 5)
            try:
                pos = 2 + 4  # version(2) + group cipher(4)
                if pos + 2 <= len(data):
                    pw_cnt = int.from_bytes(data[pos:pos+2], "little")
                    pos += 2 + 4 * pw_cnt
                if pos + 2 <= len(data):
                    akm_cnt = int.from_bytes(data[pos:pos+2], "little")
                    pos += 2
                    for _ in range(akm_cnt):
                        if pos + 4 <= len(data):
                            oui = data[pos:pos+3]
                            atype = data[pos+3]
                            if oui == b"\x00\x0f\xac":
                                if atype == 8:
                                    is_wpa3 = True
                                elif atype in (1, 5):
                                    is_enterprise = True
                        pos += 4
            except Exception:
                pass

        # 221: Vendor Specific (check WPA1 OUI 00:50:F2:01)
        elif eid == 221 and len(data) >= 4:
            if data[:4] == b"\x00\x50\xf2\x01":
                has_wpa1 = True

    if not modes:
        if freq_mhz and freq_mhz >= 5000:
            modes.add("a")
        else:
            modes.add("b/g")

    order = ["b/g", "a", "n", "ac", "ax", "be"]
    mode_str = "/".join([m for m in order if m in modes])

    if is_wpa3:
        sec_str = "WPA3-Enterprise" if is_enterprise else "WPA3-Personal"
    elif has_rsn:
        sec_str = "WPA2-Enterprise" if is_enterprise else "WPA2-Personal"
    elif has_wpa1:
        sec_str = "WPA-Personal"
    else:
        sec_str = "Open"

    return {
        "width_mhz": width_mhz,
        "mode": mode_str,
        "security": sec_str,
    }


# ---------------------------------------------------------------------------
# Windows Real Hardware Reader (wlanapi.dll + netsh)
# ---------------------------------------------------------------------------

class WindowsWiFiReader:
    def __init__(self):
        self.wlanapi = ctypes.windll.wlanapi
        self.handle = ctypes.c_void_p()
        self.iface_guid = None
        self.iface_desc = None
        self.last_scan = 0.0
        self.last_netsh = 0.0
        self.netsh_cache = {}
        self.lock = threading.Lock()
        self._init_wlan()

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WLAN_INTERFACE_INFO(ctypes.Structure):
        _fields_ = [
            ("InterfaceGuid", ctypes.c_ubyte * 16),
            ("strInterfaceDescription", ctypes.c_wchar * 256),
            ("isState", ctypes.c_int),
        ]

    class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
        _fields_ = [
            ("dwNumberOfItems", ctypes.c_ulong),
            ("dwIndex", ctypes.c_ulong),
            ("InterfaceInfo", ctypes.c_ubyte * 1),
        ]

    class DOT11_SSID(ctypes.Structure):
        _fields_ = [
            ("uSSIDLength", ctypes.c_ulong),
            ("ucSSID", ctypes.c_ubyte * 32),
        ]

    class WLAN_RATE_SET(ctypes.Structure):
        _fields_ = [
            ("uRateSetLength", ctypes.c_ulong),
            ("usRateSet", ctypes.c_ushort * 126),
        ]

    class WLAN_BSS_ENTRY(ctypes.Structure):
        _fields_ = [
            ("dot11Ssid", ctypes.c_ubyte * 36),
            ("uPhyId", ctypes.c_ulong),
            ("dot11Bssid", ctypes.c_ubyte * 6),
            ("dot11BssType", ctypes.c_int),
            ("dot11BssPhyType", ctypes.c_int),
            ("lRssi", ctypes.c_long),
            ("uLinkQuality", ctypes.c_ulong),
            ("bInRegDomain", ctypes.c_ubyte),
            ("usBeaconPeriod", ctypes.c_ushort),
            ("ullTimestamp", ctypes.c_ulonglong),
            ("ullHostTimestamp", ctypes.c_ulonglong),
            ("usCapabilityInformation", ctypes.c_ushort),
            ("ulChCenterFrequency", ctypes.c_ulong),
            ("wlanRateSet", ctypes.c_ubyte * 256),
            ("ulIeOffset", ctypes.c_ulong),
            ("ulIeSize", ctypes.c_ulong),
        ]

    def _init_wlan(self):
        neg = ctypes.c_ulong()
        res = self.wlanapi.WlanOpenHandle(2, None, ctypes.byref(neg), ctypes.byref(self.handle))
        if res != 0:
            raise RuntimeError(f"WlanOpenHandle failed (code {res})")

        list_ptr = ctypes.c_void_p()
        res = self.wlanapi.WlanEnumInterfaces(self.handle, None, ctypes.byref(list_ptr))
        if res != 0 or not list_ptr.value:
            raise RuntimeError(f"WlanEnumInterfaces failed (code {res})")

        try:
            n_items = ctypes.c_ulong.from_address(list_ptr.value).value
            if n_items == 0:
                raise RuntimeError("No Wi-Fi adapter detected.")
            # Pick first connected interface (isState == 1), else first interface
            entry_size = ctypes.sizeof(self.WLAN_INTERFACE_INFO)
            chosen = None
            for idx in range(n_items):
                info = self.WLAN_INTERFACE_INFO.from_address(list_ptr.value + 8 + idx * entry_size)
                if chosen is None or info.isState == 1:
                    chosen = info
                    if info.isState == 1:
                        break
            self.iface_guid = (ctypes.c_ubyte * 16).from_buffer_copy(chosen.InterfaceGuid)
            self.iface_desc = chosen.strInterfaceDescription
        finally:
            self.wlanapi.WlanFreeMemory(list_ptr)

    def _query_rssi_dbm(self):
        data_size = ctypes.c_ulong()
        data_ptr = ctypes.c_void_p()
        val_type = ctypes.c_int()
        # WLAN_INTF_OPCODE_RSSI = 0x10000102
        res = self.wlanapi.WlanQueryInterface(
            self.handle,
            ctypes.byref(self.iface_guid),
            0x10000102,
            None,
            ctypes.byref(data_size),
            ctypes.byref(data_ptr),
            ctypes.byref(val_type),
        )
        if res != 0 or not data_ptr.value:
            return None
        try:
            return int(ctypes.c_long.from_address(data_ptr.value).value)
        finally:
            self.wlanapi.WlanFreeMemory(data_ptr)

    def _trigger_scan_if_needed(self, interval_sec=1.5):
        now = time.monotonic()
        if now - self.last_scan >= interval_sec:
            self.last_scan = now
            try:
                self.wlanapi.WlanScan(self.handle, ctypes.byref(self.iface_guid), None, None, None)
            except Exception:
                pass

    def _read_netsh(self):
        now = time.monotonic()
        if now - self.last_netsh < 2.0 and self.netsh_cache:
            return self.netsh_cache
        self.last_netsh = now
        info = {}
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=2.5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            for line in out.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                kl = k.strip().lower()
                v = v.strip()
                if kl == "ssid" and "ssid" not in info:
                    info["ssid"] = v
                elif kl in ("bssid", "ap bssid"):
                    info["bssid"] = v.upper()
                elif kl in ("channel", "kanal"):
                    m = re.search(r"\d+", v)
                    if m:
                        info["channel"] = int(m.group())
                elif kl in ("radio type", "radiotyp"):
                    info["radio_type"] = v
                elif kl in ("authentication", "autentisering"):
                    info["security"] = v
                elif kl in ("signal",):
                    m = re.search(r"\d+", v)
                    if m:
                        info["signal_pct"] = int(m.group())
                elif "receive rate" in kl or "mottagningshastighet" in kl:
                    m = re.search(r"[\d.]+", v)
                    if m:
                        info["rx_mbps"] = float(m.group())
                elif "transmit rate" in kl or "sändningshastighet" in kl:
                    m = re.search(r"[\d.]+", v)
                    if m:
                        info["tx_mbps"] = float(m.group())
                elif kl in ("band",):
                    info["band"] = v
        except Exception:
            pass
        self.netsh_cache = info
        return info

    def _get_bss_list(self):
        bss_ptr = ctypes.c_void_p()
        # dot11_BSS_type_any = 3
        res = self.wlanapi.WlanGetNetworkBssList(
            self.handle,
            ctypes.byref(self.iface_guid),
            None,
            3,
            False,
            None,
            ctypes.byref(bss_ptr),
        )
        if res != 0 or not bss_ptr.value:
            return []

        networks = []
        try:
            base = bss_ptr.value
            n_items = ctypes.c_ulong.from_address(base + 4).value
            entry_size = ctypes.sizeof(self.WLAN_BSS_ENTRY)

            for idx in range(n_items):
                entry_addr = base + 8 + idx * entry_size
                e = self.WLAN_BSS_ENTRY.from_address(entry_addr)

                ssid_len = int.from_bytes(bytes(e.dot11Ssid[:4]), "little")
                ssid_len = min(ssid_len, 32)
                ssid_raw = bytes(e.dot11Ssid[4 : 4 + ssid_len])
                ssid = ssid_raw.decode("utf-8", errors="replace").strip("\x00")
                bssid = ":".join(f"{b:02X}" for b in e.dot11Bssid)
                freq_mhz = int(round(e.ulChCenterFrequency / 1000.0)) if e.ulChCenterFrequency else None
                channel = freq_to_channel(freq_mhz)
                band = freq_to_band(freq_mhz)

                ie_info = {"width_mhz": None, "mode": None, "security": None}
                if e.ulIeOffset and e.ulIeSize and e.ulIeSize < 4096:
                    ie_bytes = ctypes.string_at(entry_addr + e.ulIeOffset, e.ulIeSize)
                    ie_info = parse_ies(ie_bytes, freq_mhz)

                networks.append({
                    "ssid": ssid or "<Hidden>",
                    "bssid": bssid,
                    "rssi_dbm": int(e.lRssi),
                    "signal_pct": int(e.uLinkQuality),
                    "channel": channel,
                    "frequency_mhz": freq_mhz,
                    "width_mhz": ie_info["width_mhz"],
                    "band": band,
                    "mode": ie_info["mode"],
                    "security": ie_info["security"],
                })
        finally:
            self.wlanapi.WlanFreeMemory(bss_ptr)

        networks.sort(key=lambda x: x["rssi_dbm"], reverse=True)
        return networks

    def sample(self):
        with self.lock:
            self._trigger_scan_if_needed(1.5)
            rssi_direct = self._query_rssi_dbm()
            netsh = self._read_netsh()
            networks = self._get_bss_list()

            conn_bssid = netsh.get("bssid")
            matched = None
            if conn_bssid:
                for net in networks:
                    if net["bssid"] == conn_bssid:
                        matched = net
                        break
            if matched is None and netsh.get("ssid"):
                for net in networks:
                    if net["ssid"] == netsh["ssid"]:
                        matched = net
                        break

            rssi = rssi_direct if rssi_direct is not None else (matched["rssi_dbm"] if matched else None)
            freq_mhz = matched["frequency_mhz"] if matched else channel_to_freq(netsh.get("channel"))
            channel = matched["channel"] if (matched and matched["channel"]) else netsh.get("channel")
            band = (matched["band"] if matched else None) or freq_to_band(freq_mhz) or netsh.get("band")

            return {
                "timestamp": datetime.now().isoformat(timespec="milliseconds"),
                "os": f"Windows {platform.release()}",
                "adapter": self.iface_desc,
                "connected": rssi is not None,
                "ssid": netsh.get("ssid") or (matched["ssid"] if matched else None),
                "bssid": conn_bssid or (matched["bssid"] if matched else None),
                "rssi_dbm": rssi,
                "signal_pct": netsh.get("signal_pct") if netsh.get("signal_pct") is not None else (matched["signal_pct"] if matched else None),
                "channel": channel,
                "frequency_mhz": freq_mhz,
                "width_mhz": matched["width_mhz"] if matched else None,
                "band": band,
                "mode": (matched["mode"] if matched else None) or netsh.get("radio_type"),
                "security": netsh.get("security") or (matched["security"] if matched else None),
                "rx_mbps": netsh.get("rx_mbps"),
                "tx_mbps": netsh.get("tx_mbps"),
                "networks": networks,
            }


# ---------------------------------------------------------------------------
# Linux Real Hardware Reader (nmcli primary, iw for width enrichment)
# ---------------------------------------------------------------------------

def _find_binary(name, extra_dirs=()):
    """Locate an executable even when it lives in sbin dirs not on PATH."""
    from shutil import which
    found = which(name)
    if found:
        return found
    for d in extra_dirs:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _nmcli_split(line):
    """Split an nmcli -t line on unescaped ':' and un-escape '\\:' / '\\\\'."""
    fields = []
    buf = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c == "\\" and i + 1 < n:
            buf.append(line[i + 1])
            i += 2
            continue
        if c == ":":
            fields.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    fields.append("".join(buf))
    return fields


def _pct_to_dbm(pct):
    # NetworkManager maps signal quality 0-100 to roughly -110..-40 dBm.
    try:
        pct = max(0, min(100, int(pct)))
    except (TypeError, ValueError):
        return None
    return int(round(pct / 2.0 - 100))


def _nm_security(sec):
    sec = (sec or "").strip()
    if not sec:
        return "Open"
    if "WPA3" in sec:
        return "WPA3-Personal"
    if "WPA2" in sec:
        return "WPA2-Personal"
    if "WPA1" in sec or "WPA" in sec:
        return "WPA-Personal"
    if "WEP" in sec:
        return "WEP"
    return sec


class LinuxWiFiReader:
    NM_FIELDS = "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,RATE,SECURITY"

    def __init__(self):
        self.nmcli = _find_binary("nmcli", ("/usr/bin", "/bin"))
        self.iw = _find_binary("iw", ("/usr/sbin", "/sbin", "/usr/bin"))
        self.iface = self._find_iface()
        if not self.nmcli and not self.iw:
            raise RuntimeError(
                "Neither nmcli nor iw found. Install network-manager or iw."
            )

    def _find_iface(self):
        # Prefer the first wifi device nmcli reports; fall back to iw, then wlan0.
        if self.nmcli:
            try:
                out = subprocess.check_output(
                    [self.nmcli, "-t", "-f", "DEVICE,TYPE", "device"],
                    text=True, timeout=2.0,
                )
                for line in out.splitlines():
                    parts = _nmcli_split(line)
                    if len(parts) >= 2 and parts[1] == "wifi":
                        return parts[0]
            except Exception:
                pass
        if self.iw:
            try:
                out = subprocess.check_output([self.iw, "dev"], text=True, timeout=2.0)
                m = re.search(r"Interface\s+(\S+)", out)
                if m:
                    return m.group(1)
            except Exception:
                pass
        return "wlan0"

    def _blank(self):
        return {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "os": f"Linux ({platform.release()})",
            "adapter": self.iface,
            "connected": False,
            "ssid": None,
            "bssid": None,
            "rssi_dbm": None,
            "signal_pct": None,
            "channel": None,
            "frequency_mhz": None,
            "width_mhz": None,
            "band": None,
            "mode": None,
            "security": None,
            "rx_mbps": None,
            "tx_mbps": None,
            "networks": [],
        }

    def _scan_nmcli(self):
        """Return (networks list, active network dict or None)."""
        networks = []
        active = None
        if not self.nmcli:
            return networks, active
        try:
            out = subprocess.check_output(
                [self.nmcli, "-t", "-f", self.NM_FIELDS,
                 "device", "wifi", "list", "ifname", self.iface],
                text=True, timeout=4.0,
            )
        except Exception:
            # Some nmcli versions reject 'ifname' here; retry without it.
            try:
                out = subprocess.check_output(
                    [self.nmcli, "-t", "-f", self.NM_FIELDS,
                     "device", "wifi", "list"],
                    text=True, timeout=4.0,
                )
            except Exception:
                return networks, active

        for line in out.splitlines():
            if not line.strip():
                continue
            f = _nmcli_split(line)
            if len(f) < 8:
                continue
            in_use, ssid, bssid, chan, freq, signal, rate, security = f[:8]

            freq_mhz = None
            m = re.search(r"(\d+)", freq)
            if m:
                freq_mhz = int(m.group(1))

            rate_mbps = None
            m = re.search(r"([\d.]+)", rate)
            if m:
                rate_mbps = float(m.group(1))

            try:
                channel = int(chan) if chan.strip() else freq_to_channel(freq_mhz)
            except ValueError:
                channel = freq_to_channel(freq_mhz)

            try:
                pct = int(signal)
            except ValueError:
                pct = None

            net = {
                "ssid": ssid or "<Hidden>",
                "bssid": bssid.upper() if bssid else None,
                "rssi_dbm": _pct_to_dbm(pct),
                "signal_pct": pct,
                "channel": channel,
                "frequency_mhz": freq_mhz,
                "width_mhz": None,
                "band": freq_to_band(freq_mhz),
                "mode": None,
                "security": _nm_security(security),
                "_rate_mbps": rate_mbps,
            }
            networks.append(net)
            if in_use.strip() == "*":
                active = net

        networks.sort(
            key=lambda x: (x["rssi_dbm"] if x["rssi_dbm"] is not None else -999),
            reverse=True,
        )
        return networks, active

    def _enrich_with_iw(self, res):
        """Fill channel width (and anything missing) from `iw link` if available."""
        if not self.iw:
            return
        try:
            link = subprocess.check_output(
                [self.iw, "dev", self.iface, "link"], text=True, timeout=2.0
            )
        except Exception:
            return
        if "Not connected" in link:
            return
        m = re.search(r"rx bitrate:\s*([\d.]+)\s*MBit/s", link)
        if m:
            res["rx_mbps"] = float(m.group(1))
        m = re.search(r"tx bitrate:\s*([\d.]+)\s*MBit/s", link)
        if m and res.get("tx_mbps") is None:
            res["tx_mbps"] = float(m.group(1))
        m = re.search(r"(\d+)\s*MHz\s*width", link) or re.search(r"width:\s*(\d+)\s*MHz", link)
        if m:
            res["width_mhz"] = int(m.group(1))
        m = re.search(r"signal:\s*(-?\d+)\s*dBm", link)
        if m:
            res["rssi_dbm"] = int(m.group(1))
            res["signal_pct"] = max(0, min(100, int(2 * (res["rssi_dbm"] + 100))))

    def sample(self):
        res = self._blank()
        networks, active = self._scan_nmcli()

        # Drop the private helper key before exposing networks.
        res["networks"] = [{k: v for k, v in n.items() if k != "_rate_mbps"}
                           for n in networks]

        if active:
            res["connected"] = True
            res["ssid"] = active["ssid"] if active["ssid"] != "<Hidden>" else None
            res["bssid"] = active["bssid"]
            res["rssi_dbm"] = active["rssi_dbm"]
            res["signal_pct"] = active["signal_pct"]
            res["channel"] = active["channel"]
            res["frequency_mhz"] = active["frequency_mhz"]
            res["band"] = active["band"]
            res["security"] = active["security"]
            if active.get("_rate_mbps") is not None:
                res["tx_mbps"] = active["_rate_mbps"]

        # iw gives us true channel width + exact dBm when it's installed.
        self._enrich_with_iw(res)
        return res


# ---------------------------------------------------------------------------
# macOS Real Hardware Reader (system_profiler)
# ---------------------------------------------------------------------------

class MacOSWiFiReader:
    def sample(self):
        res = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "os": f"macOS {platform.mac_ver()[0]}",
            "adapter": "en0",
            "connected": False,
            "ssid": None,
            "bssid": None,
            "rssi_dbm": None,
            "signal_pct": None,
            "channel": None,
            "frequency_mhz": None,
            "width_mhz": None,
            "band": None,
            "mode": None,
            "security": None,
            "rx_mbps": None,
            "tx_mbps": None,
            "networks": [],
        }
        try:
            out = subprocess.check_output(
                ["system_profiler", "SPAirPortDataType", "-json"],
                text=True,
                timeout=4.0,
            )
            data = json.loads(out)
            ifaces = data.get("SPAirPortDataType", [{}])[0].get("spairport_airport_interfaces", [])
            if ifaces:
                iface = ifaces[0]
                res["adapter"] = iface.get("_name", "en0")
                cur = iface.get("spairport_current_network_information")
                if cur:
                    res["connected"] = True
                    res["ssid"] = cur.get("_name")
                    res["mode"] = cur.get("spairport_network_phymode")
                    res["security"] = cur.get("spairport_security_mode")
                    tx = cur.get("spairport_network_rate")
                    if tx:
                        res["tx_mbps"] = float(tx)
                    ch_str = str(cur.get("spairport_network_channel", ""))
                    m_ch = re.search(r"(\d+)", ch_str)
                    if m_ch:
                        res["channel"] = int(m_ch.group(1))
                    m_w = re.search(r"(\d+)\s*MHz", ch_str)
                    if m_w:
                        res["width_mhz"] = int(m_w.group(1))
                    if "5GHz" in ch_str or "5 GHz" in ch_str:
                        res["band"] = "5 GHz"
                    elif "6GHz" in ch_str or "6 GHz" in ch_str:
                        res["band"] = "6 GHz"
                    elif "2GHz" in ch_str or "2.4" in ch_str:
                        res["band"] = "2.4 GHz"
                    res["frequency_mhz"] = channel_to_freq(res["channel"], res["band"])
                    sig = str(cur.get("spairport_signal_noise", ""))
                    m_sig = re.search(r"(-?\d+)\s*dBm", sig)
                    if m_sig:
                        res["rssi_dbm"] = int(m_sig.group(1))
                        res["signal_pct"] = max(0, min(100, int(2 * (res["rssi_dbm"] + 100))))
        except Exception:
            pass
        return res


def create_reader():
    sys_name = platform.system()
    if sys_name == "Windows":
        return WindowsWiFiReader()
    if sys_name == "Linux":
        return LinuxWiFiReader()
    if sys_name == "Darwin":
        return MacOSWiFiReader()
    raise RuntimeError(f"Unsupported OS: {sys_name}")


def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# Gateway detection + startup prompt
# ---------------------------------------------------------------------------

GATEWAY = None  # set by prompt_for_gateway() before the server starts


def is_valid_ipv4(ip):
    if not ip:
        return False
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        if len(p) > 1 and p[0] == "0":  # reject leading zeros like 01
            return False
        if not 0 <= int(p) <= 255:
            return False
    return True


def detect_gateway():
    """Best-effort default gateway detection, no external dependencies."""
    sys_name = platform.system()
    try:
        if sys_name == "Windows":
            out = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                text=True, encoding="utf-8", errors="replace", timeout=3.0,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            for line in out.splitlines():
                cols = line.split()
                if len(cols) >= 3 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0":
                    if is_valid_ipv4(cols[2]):
                        return cols[2]

        elif sys_name == "Linux":
            try:
                out = subprocess.check_output(["ip", "route", "show", "default"],
                                              text=True, timeout=3.0)
                m = re.search(r"default via\s+([0-9.]+)", out)
                if m and is_valid_ipv4(m.group(1)):
                    return m.group(1)
            except Exception:
                pass
            # Fallback: parse /proc/net/route (gateway in little-endian hex)
            try:
                with open("/proc/net/route") as f:
                    for line in f.readlines()[1:]:
                        fields = line.split()
                        if len(fields) >= 3 and fields[1] == "00000000":
                            gw_hex = fields[2]
                            gw = ".".join(str(int(gw_hex[i:i+2], 16))
                                          for i in (6, 4, 2, 0))
                            if is_valid_ipv4(gw):
                                return gw
            except Exception:
                pass

        elif sys_name == "Darwin":
            out = subprocess.check_output(["route", "-n", "get", "default"],
                                          text=True, timeout=3.0)
            m = re.search(r"gateway:\s*([0-9.]+)", out)
            if m and is_valid_ipv4(m.group(1)):
                return m.group(1)
    except Exception:
        pass
    return None


def prompt_for_gateway():
    """Ask the user to confirm/override the gateway before the monitor starts."""
    detected = detect_gateway()
    default = detected if detected else "192.168.1.1"

    print("-" * 60)
    if detected:
        print(f"  Detected default gateway: {detected}")
    else:
        print("  Could not auto-detect a default gateway.")
    print("  Enter the gateway IP to monitor against, or press Enter to")
    print(f"  accept the default [{default}].")

    while True:
        try:
            raw = input("  Gateway IP> ").strip()
        except (EOFError, KeyboardInterrupt):
            # Non-interactive / piped stdin -> fall back to the default
            print(f"\n  No input available, using {default}.")
            return default

        candidate = raw if raw else default
        if is_valid_ipv4(candidate):
            return candidate
        print(f"  '{candidate}' is not a valid IPv4 address. Try again.")


# ---------------------------------------------------------------------------
# HTTP Server
# ---------------------------------------------------------------------------

READER = None


class WiFiRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        if self.path.startswith("/api/live"):
            try:
                payload = READER.sample()
                payload["gateway"] = GATEWAY
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                err = json.dumps({"error": str(exc), "connected": False}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(err)))
                self.end_headers()
                self.wfile.write(err)
            return
        return super().do_GET()

    def log_message(self, format, *args):
        # Keep terminal clean (suppress per-poll access logs)
        pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    global READER, GATEWAY
    print("=" * 60)
    print("  Wi-Fi RSSI Live Monitor — Real Hardware Backend")
    print("=" * 60)
    try:
        READER = create_reader()
        first = READER.sample()
        print(f"  OS / Adapter : {first.get('os')} | {first.get('adapter')}")
        if first.get("connected"):
            print(f"  Connected AP : {first.get('ssid')} ({first.get('bssid')})")
            print(f"  Radio        : {first.get('band')} | Ch {first.get('channel')} "
                  f"({first.get('frequency_mhz')} MHz) | Width {first.get('width_mhz')} MHz | {first.get('mode')}")
            print(f"  Live RSSI    : {first.get('rssi_dbm')} dBm")
        else:
            print("  Status       : Waiting for Wi-Fi connection...")
    except Exception as e:
        print(f"  ERROR initializing Wi-Fi reader: {e}")
        sys.exit(1)

    # Gateway: env var skips the prompt, otherwise ask the user before starting.
    env_gw = os.environ.get("GATEWAY", "").strip()
    if env_gw and is_valid_ipv4(env_gw):
        GATEWAY = env_gw
        print("-" * 60)
        print(f"  Gateway      : {GATEWAY} (from GATEWAY env var)")
    else:
        GATEWAY = prompt_for_gateway()
        print(f"  Gateway set  : {GATEWAY}")

    lan_ip = get_lan_ip()
    local_url = f"http://localhost:{PORT}"
    lan_url = f"http://{lan_ip}:{PORT}"
    print("-" * 60)
    print(f"  Local URL    : {local_url}")
    print(f"  Phone / LAN  : {lan_url}")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)

    server = ThreadingHTTPServer((HOST, PORT), WiFiRequestHandler)
    threading.Timer(0.8, lambda: webbrowser.open(local_url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()