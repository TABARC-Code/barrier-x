# Tor remote-link plugin 0.1.0

I keep this as an optional external transport. Barrier has no native plugin
loader: this companion runs beside the existing client and forwards its TCP
stream through a local Tor SOCKS listener to a v3 onion service. It doesn't
change the engine protocol, terminate TLS, approve peers or execute commands.
The plugin is experimental until a real onion-network session is measured.

## Requirements

Python 3.11 or newer, an operator-installed Tor implementation supporting v3
onion services and SOCKS username/password isolation, and working Barrier TLS
identities and peer approvals. No third-party Python package is required.
Tor isn't downloaded, bundled, started or reconfigured automatically.
As reviewed on 10 November 2026, use C Tor 0.4.9.16 or a newer supported,
patched stable release. Tor 0.4.8 is end-of-life. The plugin cannot determine
Tor's version through SOCKS; the operator must check it and keep it updated.

The bridge is portable Python. Automated service-folder provisioning is POSIX
only and rejects symlink ancestors, including platform aliases. Use a canonical
absolute folder path. Windows service provisioning needs the manual Tor setup
below, with owner-only profile permissions. Native Windows/macOS runs are still
needed; a Linux test doesn't sign those off.

## Connection arrangement

The input-sharing server runs on the machine accepting the connection. Its Tor
service maps virtual port 24800 to the engine's loopback port 24800. The other
machine runs Tor, this plugin and the ordinary Barrier client. That client
connects to 127.0.0.1:24801. Only the Tor SOCKS listener receives the onion name.
The plugin makes no direct connection to the remote machine and has no fallback.

Bind the **server engine to 127.0.0.1:24800** using its existing `--address`
option or the GUI's interface setting. Keep encryption enabled and verify the
full public peer fingerprints by a separate trusted route. The plugin carries
opaque bytes, so it cannot enforce an engine TLS setting or grant peer approval.
Don't expose a second engine listener on a public or LAN interface by accident.

## Install or remove

From the repository:

```sh
python3 plugins/tor/build_plugin.py --output barrier-x-tor.pyz
python3 barrier-x-tor.pyz --help
```

Or configure the existing build with `-DBARRIER_BUILD_TOR_PLUGIN=ON`, then build
target `barrier-tor-plugin`. The archive is written under build/plugins/tor.
CMake installation places it under share/barrier-x/plugins/tor. Install just
this component with `cmake --install build --component tor-plugin --prefix DIR`. It isn't enabled
by the normal application build. Copy the archive wherever you keep optional
tools; `python` may be the command name on Windows. Stop it and remove that
archive to uninstall the bridge. Tor identities and approvals remain separate.
To withdraw the server's onion endpoint, stop its dedicated Tor instance as well.
The archive includes this guide, the manifest and the repository licence.

## Prepare the private service

Generate a client-authorisation X25519 key pair using the
[Tor client-authorisation guide](https://community.torproject.org/onion-services/advanced/client-auth/).
Send only its canonical 52-character base32 **public** key to the server operator.
The private key belongs in the connecting machine's Tor ClientOnionAuthDir;
never put it in command arguments, the repository or a shared clipboard.

On POSIX, choose a fresh profile below an existing safe directory. Run as the
ordinary account which will run this dedicated Tor instance:

```sh
python3 barrier-x-tor.pyz provision-service \
  --directory "$HOME/barrier-onion" \
  --client-public-key "$CLIENT_PUBLIC_KEY"
tor --verify-config -f "$HOME/barrier-onion/torrc"
tor -f "$HOME/barrier-onion/torrc"
```

`CLIENT_PUBLIC_KEY` is the public key from the preceding step. Provisioning
creates private folders and an authorised-client file before writing the torrc.
It refuses an existing profile and doesn't repair ancestor permissions. On a
failed provision, inspect the new folder before removing it; no config is written
until the authorisation file is complete. Do not launch a partial profile.
The generated config disables the server's SOCKS listener and forwards only to
127.0.0.1. Tor creates and retains its onion identity. Read the address from
barrier-onion/onion/hostname once Tor has started successfully.

For Windows, configure a dedicated Tor service using the official guide: a
private HiddenServiceDir, HiddenServiceVersion 3 and HiddenServicePort 24800
127.0.0.1:24800. Install the client's public key in an authorized_clients/*.auth
file using the exact `descriptor:x25519:PUBLIC_KEY` format. Apply owner-only
permissions before starting Tor. This plugin doesn't implement Windows ACL setup.

**Check Tor actually loads the authorisation file.** Tor enables client
authorisation only when it loads at least one valid file. Removing the last valid
file can make the service public to anyone with its address. A successful preset
write doesn't prove Tor loaded it. Test access from a Tor client without the
private authorisation key: it must fail. Stop the service rather than emptying
its authorisation folder. Restart Tor when changing or revoking authorisation.

## Prepare the connecting Tor and start the bridge

Configure that machine's Tor with a private ClientOnionAuthDir and a loopback
SOCKS listener, for example:

```text
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth
ClientOnionAuthDir /absolute/private/tor-client-auth
```

Following Tor's guide, put the onion service's corresponding .auth_private file
in that directory, restrict its permissions, then restart that Tor instance.
Use the actual complete onion address and run:

```sh
python3 barrier-x-tor.pyz connect --onion "$ONION_ADDRESS"
```

Set the ordinary Barrier client to manual server address 127.0.0.1 and port
24801. Retain its existing screen name, TLS identity and peer approval. LAN
DNS-SD cannot discover an onion service. Additional targets need separate bridge
processes with different local ports; each instance has exactly one fixed target.

Ctrl+C stops the bridge and closes active connections. On POSIX, SIGTERM also
stops it cleanly. The existing Barrier client decides whether to reconnect; each
new connection gets a fresh SOCKS stream and isolation value. Input isn't stored
or replayed after reconnect. Recheck local input recovery before using remote
control unattended.

## Limits and security boundaries

Default limits: one active session, up to four explicitly selected; 30 seconds
for SOCKS setup and blocked writes; one hour without incoming data in either
pump; five seconds to finish the reverse half of a closed stream. CLI options
can change these timeouts, up to one day. Every SOCKS field is parsed with an
exact bounded length. Forwarding reads 16 KiB at a time and applies write
backpressure. Reader limits are 64 KiB pause thresholds, not exact total-memory
ceilings; asyncio can overshoot them and kernel buffers are additional.

Only a checksum-valid v3 onion destination is accepted. The listener and SOCKS
connection are fixed to IPv4 loopback. SOCKS username/password values provide
Tor stream isolation, **not peer authentication**. The requested isolation
format is documented by Tor and is compatible with legacy isolation handling.
There is no no-auth SOCKS downgrade, direct-IP route or payload logging. Only
an aggregate failed-session count is printed at shutdown. Loopback still permits
other local users to reach the bridge; engine TLS and peer trust remain necessary.
An untrusted program impersonating the local Tor listener isn't authenticated by
this plugin. The protected endpoint and Tor service are operator responsibilities.

An onion address authenticates Tor's service identity; it doesn't prove the
person operating it should control your keyboard. Retain Barrier approval and
verify both sets of identity material. Tor provides no fixed latency guarantee.
Mouse movement, timeouts, sleep/reconnect and held-key recovery need real-world
measurement. This isn't remote desktop video, a VPN or a reviewed-action runner.

Provisioning doesn't audit extended ACLs, serialise later profile edits, guarantee
crash durability or protect against root/same-user tampering. Tor service/client
key rotation, revocation and backups follow Tor's own procedures.

## Checks

```sh
python3 -m unittest discover -s plugins/tor -p 'test_*.py' -v
```

The suite uses controlled local SOCKS peers and real TLS sockets. It covers
fragmented/malformed replies, refusal of auth downgrade, 2 MiB binary transfer,
EOF and bounded half-close, stalled reads/writes, pending-handshake shutdown,
connection caps, reconnect isolation, onion checksums, private provisioning and
unsafe ancestors. The TLS case accepts a trusted certificate and rejects an
untrusted one across the bridge. It doesn't contact public Tor or substitute
for a real authorised/unauthorised onion-service check.

References: [Tor SOCKS specification](https://spec.torproject.org/socks-extensions),
[onion setup](https://community.torproject.org/onion-services/setup/),
[client authorisation](https://community.torproject.org/onion-services/advanced/client-auth/).
