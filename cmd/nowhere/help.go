package main

const helpText = `Usage:
  nowhere
  nowhere <nw3-url>
  nowhere <nw2-url>
  nowhere generate-key
  nowhere fingerprint <nowhere-url>
  nowhere probe <vector-url> <target>
  nowhere -h | --help
  nowhere -v | --version

A URL without up, down, mux, next, or socks starts Nowhere 3 (ALPN nw3 only).
A URL that uses any of those options starts Nowhere 2 (ALPN nw2 only).
The two versions do not handshake with each other. One process runs one version.

Commands:
  <portal-url>     Run the Portal relay.
  <vector-url>     Run the Vector SOCKS5 client.
  <egress-url>     Run a Nowhere 3 Egress exit (QUIC only).
  generate-key     Print 16 random bytes as 32 lowercase hex characters.
  fingerprint      Print the leaf certificate SHA-256 over TCP.
  probe            End-to-end TCP flow setup; sends no application payload.
  -h, --help       Print this help message.
  -v, --version    Print version and target platform.

Nowhere 3 (default), shared key exactly 32 lowercase hex, morph defaults on:
  portal://<key>@<host>:<port>[?out=direct|egress|<socks>]
  portal://<key>@<host>/<carrier>:<port>[/<carrier>:<port>]
  vector://<key>@<host>:<port>?in=<socks-listen>
  vector://<key>@<host>/udp:<port>?in=<socks-listen>
  egress://<key>@<host>:<port>
  nowhere://<key>@<host>:<port>[?net=tcp|udp&morph=0|1]   fingerprint

Nowhere 2, selected only by up/down/mux/next/socks. Morph defaults off:
  portal://<key>@<host>:<port>?socks=<proxy>
  portal://<key>@<host>:<port>?next=<key>@<upstream>
  vector://<key>@<host>:<port>?up=tcp&down=tcp&socks=<listen>

Examples:
  nowhere generate-key
  nowhere 'portal://<generated-key>@*:2000'
  nowhere 'vector://<generated-key>@127.0.0.1:2000?in=127.0.0.1:1080&morph=0'
  nowhere 'portal://<generated-key>@*:2000/udp:2001?out=egress'
  nowhere 'egress://<generated-key>@127.0.0.1:2001?pin=<sha256>'
  nowhere 'vector://<generated-key>@127.0.0.1:2000?socks=:1080'

Nowhere 3 options:
  in=<socks>          Vector SOCKS5 listener. Required except for probe.
  out=direct|egress|<socks>
                      Portal exit. Default: direct. egress needs QUIC.
  morph=0|1           Default: 1. Peers must agree. Not negotiated.
  rate, etar          Upload and download caps in Mbps. Default: 0 (unlimited).
  sni, pin            Vector and Egress certificate checks.
  tls, crt, key       Portal certificate. tls=1 is generated. tls=2 needs files.
  dial, dial4, dial6  Outbound source bind. Conflicts with out=egress.

Nowhere 2 options (unchanged): morph default 0, up/down/mux, socks, next,
Portal keys of 32-64 lowercase hex, and free-form Vector keys.

Environment:
  NOW_MORPH_TCP_PRELUDE          nw3 TCP Morph prelude: fade (default), full8, or low7.
                                 A 3.1 Portal accepts an authenticated prelude and,
                                 for this release, still accepts a tag mismatch on
                                 the 3.0 path. Peers do not negotiate the policy.
                                 nw2 stays full8 (default) or low7 and rejects fade.

The TUI and status observer are not included in this Go binary.
`
