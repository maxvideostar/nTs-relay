# nTs-relay (StreamHub)

Server de redistribuire MPEG-TS, alternativă ușoară la Astra Cesbo, scris în Go (un singur binar, fără dependențe externe).
Fluxul TS trece **neatins, byte cu byte**: PAT, PMT, PID-urile video/audio, teletext, subtitrări și SDT rămân cele originale.

## Instalare

```bash
sudo bash install-streamhub.sh            # port implicit 4000
sudo PORT=8100 bash install-streamhub.sh  # port custom
```

Scriptul instalează Go (dacă lipsește), ffmpeg și srt-tools, compilează binarul în `/usr/local/bin/streamhub`,
creează `/etc/streamhub/config.json` (parolă admin și token generate automat) și serviciul systemd `streamhub`.
Rulat din nou, actualizează binarul și păstrează config-ul.

## Windows

Descarcă `streamhub-<versiune>-windows-x64.zip` din [Releases](https://github.com/maxvideostar/nTs-relay/releases),
pune `streamhub.exe` într-un folder fix (ex. `C:\StreamHub`) și dă dublu-click: creează `config.json` lângă exe
și deschide panoul în browser (http://127.0.0.1:4000/).

- `streamhub.exe -install` — pornire automată cu Windows, în fundal (task programat ca SYSTEM, repornire automată) + regulă de firewall
- `streamhub.exe -uninstall` — oprește și elimină pornirea automată
- jurnal în `streamhub.log`; pentru SRT/RTMP pune `ffmpeg.exe` lângă `streamhub.exe`

## Intrări

| Format | Exemplu | PID-uri originale |
|---|---|---|
| UDP multicast/unicast | `udp://eth0@239.1.1.1:1234`, `udp://0.0.0.0:5000` | da |
| RTP | `rtp://@239.1.1.1:5000` | da |
| HTTP-TS | `http://server/stream.ts` | da |
| HLS (segmente .ts, AES-128) | `http://server/live.m3u8` | da |
| HLS fMP4 / CMAF (detectat automat, prin ffmpeg, fără recodare) | `https://server/live/master.m3u8` | nu — fMP4 nu are PID-uri (video 0x100, audio 0x101, PMT 0x1000) |
| SRT | `srt://host:9000?mode=caller`, `srt://:9000?mode=listener` | da |
| RTMP pull / push | `rtmp://host/app/key`, `rtmp-listen://0.0.0.0:1935/live/key` | nu — RTMP nu are PID-uri (video 0x100, audio 0x101, PMT 0x1000) |

Mai multe intrări pe un canal = backup automat: comutare în ~5s, revenire pe sursa principală când reapare (verificare la 60s).

## Ieșiri

- **Clienți:** tabul „Clienți” din panou arată IP, canal, format, player, viteză, transferat și durata fiecărei conexiuni
- **HTTP-TS:** `http://IP:4000/<id>` (ex. `http://netstreaming.eu:4000/hd365`, compatibil cu linkurile Astra) — clienții noi pornesc pe keyframe, cu PAT/PMT în față
- **HLS:** `http://IP:4000/<id>.m3u8` sau `http://IP:4000/<id>/index.m3u8` — segmente în memorie, tăiate pe keyframe
- ID-ul nu ține cont de litere mari/mici (`/HD365` = `/hd365`); formele vechi `/play/<id>` și `/hls/<id>/index.m3u8` merg în continuare
- canalele ne-publice cer `?token=<token>` la final
- **UDP/multicast:** `udp://[iface@]239.10.0.1:1234?ttl=8`

## Panou web

`http://IP:4000/` (autentificare admin): status canale, bitrate, erori CC per PID, limbi, stream criptat,
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
./build.sh   # dist/: streamhub-linux-amd64, streamhub-linux-arm64, streamhub.exe, zip Windows
```

Exemplu de configurare: [`config.example.json`](config.example.json). Loguri: `journalctl -u streamhub -f`.

## Limitări

Fără plăci DVB, fără decriptare CAM.
