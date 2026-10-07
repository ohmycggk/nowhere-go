package main

const helpText = `Usage:
  nowhere
  nowhere <portal-or-vector-url>
  nowhere generate-key
  nowhere fingerprint <nowhere-url>
  nowhere probe <vector-url> <target>
  nowhere -h | --help
  nowhere -v | --version

Commands:
  <portal-url>     Run the Portal relay service.
  <vector-url>     Run the Vector native SOCKS5 client.
  generate-key     Print 16 random bytes as 32 lowercase hex characters.
  fingerprint      Print the leaf certificate SHA-256 over TCP; supports Morph.
  probe            End-to-end TCP Flow setup; sends no application payload.
  -h, --help       Print this help message.
  -v, --version    Print version and target platform.

URL forms:
  portal://<key>@<listen-host>:<port>[?<options>]
  portal://<key>@<listen-host>/<carrier>:<port>[/<carrier>:<port>][?<options>]
  vector://<key>@<portal-host>:<port>?socks=<listener>[&<options>]
  vector://<key>@<portal-host>/<carrier>:<port>[/<carrier>:<port>]?socks=...
  nowhere://<key>@<portal-host>:<port>[?<options>][#<name>]  For fingerprint
  nowhere://<key>@<portal-host>/tcp:<port>[/udp:<port>][?<options>][#<name>]

Endpoint syntax:
  host:port                   Use TCP and UDP on the same port.
  tcp, udp                    Use any address family.
  tcp4, udp4 / tcp6, udp6     Restrict a carrier to IPv4 or IPv6.
  *                           Portal wildcard; clients require a concrete host.

Examples:
  nowhere 'portal://<generated-key>@*:2000'
  nowhere 'portal://<generated-key>@*/tcp:2006/udp:2017?morph=1'
  nowhere 'portal://<generated-key>@:2000?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem'
  nowhere 'portal://<generated-key>@:2000?socks=127.0.0.1:1080'
  nowhere 'portal://<generated-key>@:2000?next=<upstream-key>@origin.example:2000'
  nowhere 'vector://<generated-key>@127.0.0.1:2000?up=tcp&down=tcp&socks=:1080'
  nowhere 'vector://<generated-key>@127.0.0.1/tcp:2006/udp:2017?socks=127.0.0.1:1080'
  nowhere generate-key
  nowhere fingerprint 'nowhere://<generated-key>@relay.example:2000#My%20Portal'
  nowhere probe 'vector://<generated-key>@relay.example:2000' 'example.com:443'

Common options:
  morph=0|1           Enable keyed wire masking. Default: 0.
  log=<level>         none, debug, info, warn, or error. Default: info.

Portal options:
  Listener and next shared keys must be 32–64 lowercase hex characters.
  tls=1|2             Generated certificate or supplied PEM files. Default: 1.
  crt=<path>          PEM certificate chain for tls=2.
  key=<path>          PEM private key for tls=2.
  dial=<ip|auto>      Outbound source IP and single-family restriction, or auto.
  dial4=<ipv4|auto>   IPv4 source in dual-stack mode. Default: auto.
  dial6=<ipv6|auto>   IPv6 source in dual-stack mode. Default: auto.
                      dial is mutually exclusive with dial4/dial6. Default: auto.
  socks=<proxy>       Outbound SOCKS5 proxy; mutually exclusive with next.
  next=<portal>       Native upstream Portal: key@host or key@host/<carriers>.

Vector options:
  socks=<listener>    Local SOCKS5 listener: [user:pass@]host:port. Optional for probe.

Client route options (Vector and Portal next):
  up=tcp|udp          Upload carrier. Default: the only carrier, otherwise TCP.
  down=tcp|udp        Download carrier. Default: the only carrier, otherwise TCP.
  mux=0|1             Enable TLS multiplexing when TCP is available. Default: 0.
  sni=<name|none>     Override the verified server name. Default: endpoint host.
  pin=<sha256|none>   Pin the Portal certificate SHA-256 fingerprint.
                      Without pin, system CA and server-name verification are required.

Environment:
  NOW_MORPH_TCP_PRELUDE          Client TCP Morph prelude: full8 (default) or low7.

The TUI and status observer are not included in this Go binary; use the Rust nowhere tui.
`
