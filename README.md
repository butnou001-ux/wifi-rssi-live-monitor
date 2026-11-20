# Wi-Fi RSSI Live Monitor & Heatmap

A lightweight, general-purpose, open-source web dashboard for monitoring **real-time Wi-Fi signal strength (RSSI in dBm)**, **channel width (20 / 40 / 80 / 160 MHz)**, **frequency**, **movement/variance**, and **nearby Wi-Fi networks** directly from your own computer's wireless adapter.

No hardcoded router names. No simulated data. Zero external Python dependencies.

## Features

- **Real Hardware Telemetry:** Automatically detects your currently connected SSID, BSSID, Band (`2.4 / 5 / 6 GHz`), Channel, Center Frequency (MHz), Channel Width (`20 / 40 / 80 / 160 MHz`), Wi-Fi Mode (`n / ac / ax / be`), Security, and Rx/Tx Link Speed.
- **802.11 Beacon IE Parsing (Windows):** Uses `wlanapi.dll` (`WlanQueryInterface` + `WlanGetNetworkBssList`) to parse raw 802.11 Information Elements (HT/VHT/HE/EHT Operation) — the same mechanism used by professional Wi-Fi analyzers like NetSpot.
- **Live "Heart-Rate" Signal Trace:** Smooth 60fps HTML5 Canvas waveform showing raw hardware dBm, 5-second moving average, and an interactive locked baseline (`B` key) to measure dB drops as you walk around or relocate your laptop.
- **Live RSSI Density Heatmap:** Time-binned (5 s) vs 1 dB density heatmap highlighting signal stability and fading during human movement.
- **Motion / Stability Indicator:** Computes rolling 10-second standard deviation ($\sigma$) to flag stationary vs moving conditions.
- **Nearby Networks Inspector:** Live table of surrounding Wi-Fi access points with Band filters, search, Channel Width, Mode, and live Min / Avg / Max tracking.
- **Cross-Device Viewing:** Runs a local web server on port `8000` so you can also open the dashboard from your phone or another laptop on the same Wi-Fi network (`http://<your-local-ip>:8000`).
- **CSV Export & Import:** Export any live recording to UTF-8 CSV or import existing RSSI CSV files.

## Quick Start (10 Seconds)

Requires **Python 3.8+** (standard library only — no `pip install` needed).

```bash
git clone https://github.com/<your-username>/wifi-rssi-live-monitor.git
cd wifi-rssi-live-monitor
python server.py
```

Your browser will automatically open **`http://localhost:8000`**.

## OS Support

| OS | Method Used | Live RSSI (dBm) | Channel & Freq | Channel Width (20/40/80/160 MHz) | Nearby AP Table |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Windows** | `wlanapi.dll` + `netsh` | Yes | Yes | Yes (via 802.11 IE parsing) | Yes |
| **Linux** | `iw` | Yes | Yes | Yes | Connected AP |
| **macOS** | `system_profiler` | Yes | Yes | Yes | Connected AP |

## Honest Technical Notes

- **Why a local `server.py` is required:** Web browsers strictly block websites from reading raw Wi-Fi adapter hardware directly. Running `server.py` locally bridges your OS's wireless API to the browser at `localhost:8000`.
- **RSSI vs CSI:** Standard consumer Wi-Fi drivers report a single combined integer RSSI value (1 dB resolution) per adapter rather than per-subcarrier Channel State Information (CSI).
- **Driver Refresh Rate:** Some wireless drivers cache RSSI between scans. On Windows, `server.py` triggers `WlanScan` every 1.5 seconds and the dashboard displays the repetition rate so you can always see how frequently your adapter refreshes.
