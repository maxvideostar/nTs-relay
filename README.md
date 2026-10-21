# nTs-relay (StreamHub)

Server de redistribuire MPEG-TS, alternativă ușoară la Astra Cesbo, scris în Go (un singur binar, fără dependențe externe).
Fluxul TS trece **neatins, byte cu byte**: PAT, PMT, PID-urile video/audio, teletext, subtitrări și SDT rămân cele originale.

## Instalare

```bash
sudo bash install-streamhub.sh            # port implicit 8000
sudo PORT=8100 bash install-streamhub.sh  # port custom
```

Scriptul instalează Go (dacă lipsește), ffmpeg și srt-tools, compilează binarul în `/usr/local/bin/streamhub`,
creează `/etc/streamhub/config.json` (parolă admin și token generate automat) și serviciul systemd `streamhub`.
Rulat din nou, actualizează binarul și păstrează config-ul.

## Intrări

| Format | Exemplu | PID-uri originale |
|---|---|---|
| UDP multicast/unicast | `udp://eth0@239.1.1.1:1234`, `udp://0.0.0.0:5000` | da |
| RTP | `rtp://@239.1.1.1:5000` | da |
| HTTP-TS | `http://server/stream.ts` | da |
| HLS (segmente .ts, AES-128) | `http://server/live.m3u8` | da |
| SRT | `srt://host:9000?mode=caller`, `srt://:9000?mode=listener` | da |
| RTMP pull / push | `rtmp://host/app/key`, `rtmp-listen://0.0.0.0:1935/live/key` | nu — RTMP nu are PID-uri (video 0x100, audio 0x101, PMT 0x1000) |

Mai multe intrări pe un canal = backup automat: comutare în ~5s, revenire pe sursa principală când reapare (verificare la 60s).

## Ieșiri

- **HTTP-TS:** `http://IP:8000/play/<id>?token=<token>` — clienții noi pornesc pe keyframe, cu PAT/PMT în față
- **HLS:** `http://IP:8000/hls/<id>/index.m3u8?token=<token>` — segmente în memorie, tăiate pe keyframe
- **UDP/multicast:** `udp://[iface@]239.10.0.1:1234?ttl=8`

## Panou web

`http://IP:8000/` (autentificare admin): status canale, bitrate, erori CC per PID, limbi, stream criptat,
clienți conectați, adăugare/editare/ștergere canale, tokeni, setări HLS.

## API (Basic Auth)

| Metodă | Endpoint | Descriere |
|---|---|---|
| GET | `/api/status` | starea tuturor canalelor |
| GET | `/api/config` | configurația |
| POST | `/api/channel` | canal nou (JSON `ChannelConfig`) |
| POST | `/api/channel?old=<id>` | editare canal |
| DELETE | `/api/channel?id=<id>` | ștergere |
| POST | `/api/restart?id=<id>` | repornire canal |
| POST | `/api/settings` | tokeni, HLS, parolă admin |

## Compilare manuală

```bash
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o streamhub .
./streamhub -config config.json
```

Exemplu de configurare: [`config.example.json`](config.example.json). Loguri: `journalctl -u streamhub -f`.

## Limitări

Fără plăci DVB, fără decriptare CAM, fără HLS fMP4 la intrare.
