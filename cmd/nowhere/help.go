package main

const helpText = `Usage:
  nowhere
  nowhere <portal-or-vector-url>
  nowhere -h | --help
  nowhere -v | --version

Commands:
  <portal-url>     Run the Portal relay service.
  <vector-url>     Run the Vector native SOCKS5 client.
  -h, --help       Print this help message.
  -v, --version    Print version and target platform.

Portal URL:
  portal://<shared-key>@<listen-host>:<listen-port>[?<parameters>]
  portal://<shared-key>@<listen-host>/<carrier>:<port>[/<carrier>:<port>]

Vector URL:
  vector://<shared-key>@<portal-host>:<portal-port>?socks=<listen-endpoint>[&<parameters>]
  vector://<shared-key>@<portal-host>/<carrier>:<port>[/<carrier>:<port>]?socks=...

Examples:
  nowhere 'portal://secret@:2000'
  nowhere 'portal://secret@*/tcp4:2006?log=info'
  nowhere 'portal://secret@*/tcp:2006/udp:2017'
  nowhere 'portal://secret@:2000?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem'
  nowhere 'portal://secret@:2000?socks=127.0.0.1:1080'
  nowhere 'portal://relay-key@:2000?next=upstream-key@origin.example:2000'
  nowhere 'vector://secret@127.0.0.1:2000?up=tcp&down=tcp&socks=:1080'
  nowhere 'vector://secret@127.0.0.1/tcp:2006/udp:2017?socks=127.0.0.1:1080'

The TUI is not included in this Go binary; use the Rust nowhere tui observer.
`
