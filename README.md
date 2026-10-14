# ue3sniff

A passive sniffer and decoder for **Unreal Engine 3** game network traffic.

`ue3sniff` captures UDP traffic between a UE3 client and server (live or from a
`.pcap` file), optionally decrypts it, splits packets into bunches and decodes
replicated fields and RPC calls using a per-game **profile**. It is meant for
reverse-engineering and documenting the network protocol of UE3 games, for
example to build server emulators.

Game-specific knowledge lives in JSON profiles, not in the code. The
repository ships a stock UE3 template and a profile for **APB Reloaded**.

```
11:53:20.000 C2S pkt=77 ch=2(Actor) seq=5 PlayerController.ServerCSAKeyPressed#343 (InputMapping=3, AimRotation=16384, CameraCollidePercent=<default>, Target=channel:42) bits=0..88/88 payload=07000000020001005805
```

## Features

- UE3 packet and bunch parsing (ACK and data bunches, open/close/reliable flags,
  channel index, sequence and type), with bit widths taken from the profile
- Optional packet cipher: BTEA/XXTEA with a configurable round count
- Field stream decoding by class: `SerializeInt` field indices, fixed-width
  properties and RPC parameters (`bool`, `byte`, `int`, `uint`, `float`,
  `enum`, `bits`, `object`, `string`, `rotator`)
- `-watch` mode that prints only selected fields: names, indices, ranges or
  named groups from the profile
- Exploratory mode: decodes the first packet of each UDP payload length and
  prints unknown fields and raw bunches so you can map them
- Text output for reading, JSON Lines output for scripts
- Live capture or offline `.pcap`/`.pcapng` files

## Requirements

- Go 1.26+
- Windows: [Npcap](https://npcap.com/). To capture localhost traffic, install
  it with loopback support and use the `\Device\NPF_Loopback` interface.
- Linux/macOS: libpcap (`libpcap-dev` on Debian/Ubuntu) and a C toolchain,
  because gopacket uses cgo there.

Live capture usually needs administrator/root rights.

## Install

```sh
go install github.com/quette/ue3sniff/cmd/ue3sniff@latest
```

or from a checkout:

```sh
go build ./cmd/ue3sniff
```

## Usage

List interfaces:

```sh
ue3sniff -list-devices
```

Explore traffic of a game with no profile yet (stock UE3 layout, no cipher):

```sh
ue3sniff -device 3 -server-port 7777 -log-level debug
```

Watch the APB CSA RPCs of one encrypted session:

```powershell
ue3sniff `
    -profile apb `
    -device "\Device\NPF_Loopback" `
    -server-port 6969 `
    -client-port 52601 `
    -key 00112233445566778899AABBCCDDEEFF `
    -watch csa
```

Decode every packet of a saved capture as JSON Lines:

```sh
ue3sniff -profile apb -pcap session.pcapng -server-port 6969 -key ... -all -format json > fields.jsonl
```

Decoded events go to **stdout**. Diagnostics go to **stderr**, so you can
redirect them separately.

### Flags

| Flag | Description |
|---|---|
| `-profile` | Built-in profile name (`ue3`, `apb`) or path to a JSON profile. Default `ue3`. |
| `-device` | Capture interface, by index or name. |
| `-pcap` | Read from a capture file instead of a live interface. |
| `-list-devices` | List interfaces and exit. This also runs when neither `-device` nor `-pcap` is given. |
| `-server-port` | Game server UDP port. Also used to label packets `C2S`/`S2C`. |
| `-client-port` | Client UDP port. Optional; restricts the capture to one session. |
| `-filter` | Custom BPF filter. Overrides the port flags. |
| `-key` | Session key as hex, for profiles that define a cipher. |
| `-watch` | Print only matching fields. Comma-separated watch groups, field names, `Class.Field`, indices or ranges (`338-345`). Implies `-all`. |
| `-all` | Decode every packet, not only the first packet of each payload length. |
| `-format` | `text` (default) or `json`. |
| `-log-level` | `error`, `info` (default), `debug` or `trace`. |

### Finding the client port

The client often uses a random UDP port. On Windows you can look it up from the
game process:

```powershell
Get-NetUDPEndpoint -OwningProcess (Get-Process <GameProcessName>).Id |
    Select-Object LocalAddress, LocalPort
```

You can also leave out `-client-port`, which captures every session on the
server port.

### Decryption order

When a key is set, `ue3sniff` first tries to parse a payload as plaintext and
only then decrypts it. This keeps unencrypted handshake and login traffic
readable. In `-watch` mode the session is assumed to be established, so it
tries decryption first.

## Profiles

A profile is a JSON file. See [`profile/builtin/apb.json`](profile/builtin/apb.json)
for a full example and [`profile/builtin/ue3.json`](profile/builtin/ue3.json)
for a minimal starting point.

```jsonc
{
  "name": "My UE3 Game",

  // Bit widths of the packet and bunch headers.
  "layout": {
    "packet_id_bits": 14,      // packet ID at the start of every packet
    "header_skip_bits": 0,     // extra header bits to ignore after the ID
    "ack_has_id_flag": false,  // ACK bunch has a presence bit before the ID
    "ack_id_bits": 14,
    "channel_index_bits": 10,
    "sequence_bits": 10,
    "channel_type_bits": 3,
    "bunch_size_bits": 12
  },

  // "none" or "btea". rounds = 0 uses the standard XXTEA schedule (6 + 52/n).
  "cipher": { "algorithm": "btea", "rounds": 6 },

  "channel_types": { "1": "Control", "2": "Actor", "3": "File" },

  // Bind channel indices to classes whose fields should be decoded.
  "channels": { "2": "PlayerController" },

  "classes": {
    "PlayerController": {
      // SerializeInt bound of the field index: number of replicated
      // properties and RPCs in the class's net cache.
      "field_max": 634,
      "fields": {
        // Fixed-width property; total_bits includes the index itself.
        "78": { "name": "SomeProperty", "total_bits": 66 },

        // RPC with known parameters.
        "345": {
          "name": "ServerCSAKeyReleased",
          "params": [ { "name": "InputMapping", "type": "int" } ]
        },

        // Known name, unknown layout: decoding stops here and the rest of
        // the bunch is shown as this field's payload.
        "90": { "name": "ServerUpdateLevelVisibility" }
      }
    }
  },

  // Named selections for -watch.
  "watch": { "csa": ["338-345", "426-427"] }
}
```

The real file must be plain JSON, so leave out the comments.

### Field decoding rules

- The field index is read with UE3 `SerializeInt(field_max)`. Its width can
  vary with the value; for example, 345 under 634 uses 9 bits.
- Every non-`bool` RPC parameter has a one-bit "non-default" flag before it.
  A cleared flag means the parameter has its default value and carries no
  payload. If a game sends a parameter unconditionally, set
  `"no_presence_bit": true` on it.
- If the bunch ends, the remaining parameters are reported as defaults.
- A field with `"params": []` is an RPC with no parameters. A field that has
  neither `params` nor `total_bits` has an unknown width. Decoding stops at
  such a field, because guessing the width would corrupt every field after
  it.
- `object` is a channel flag followed by `SerializeInt` of either the actor
  channel (max 1023) or the package-map NetIndex.

### Parameter types

| Type | Encoding |
|---|---|
| `bool` | 1 bit, with no presence flag |
| `byte` | 8 bits |
| `int` / `uint` | 32 bits, signed / unsigned |
| `float` | 32-bit IEEE 754 |
| `enum` | `SerializeInt(max)`; requires `max` |
| `bits` | raw `bits` bits (1–32) |
| `object` | object reference (see above) |
| `string` | `FString`: int32 length (negative means UTF-16) and characters |
| `rotator` | `FRotator::SerializeCompressed`: 3 × (presence bit + 8 bits) |

## Adding a new game

1. Copy `profile/builtin/ue3.json` and capture some traffic with
   `-log-level debug`. If no packets parse, adjust `layout`, or set up the
   cipher and key.
2. Find the channel that carries the player controller (usually a low actor
   channel opened early in the session) and bind it in `channels`.
3. Set `field_max` from the game's class data, then name the fields as you
   identify them. Exploratory mode prints `UNKNOWN` for every index it cannot
   step over.
4. Describe RPC parameters, check them with `-watch`, and send a PR with the
   profile.

## Project layout

```
cmd/ue3sniff/   CLI: capture loop, output, statistics
capture/        live/offline capture and BPF filter helpers
crypto/         packet ciphers (BTEA/XXTEA)
ue3/            bit reader and UE3 packet/bunch parser
profile/        profile schema, field/RPC decoder, built-in profiles
logger/         minimal leveled logger
```

## Acknowledgements

The APB packet layout and field tables were cross-checked against
APBEMU.

## Disclaimer

This is a passive analysis tool for interoperability research. It only reads
traffic and never injects or modifies packets. Use it only on traffic and
software you are allowed to analyze, and follow the terms of the games you
study.

## License

[MIT](LICENSE)
