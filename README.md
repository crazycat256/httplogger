# httplogger

MITM HTTP and WebSocket logger for security testing. Runs a local TLS-intercepting proxy, records matching traffic to disk, and can launch a browser preconfigured to trust the generated CA.

https://github.com/user-attachments/assets/ad0b6f96-381a-42aa-8666-74d7da38216b

## Requirements

- Rust
- A Chromium- or Firefox-based browser (for `launch`)
- `certutil` (NSS tools) to install the CA into the isolated browser profile

## Quick start

```bash
cargo build --release

# Create config.yml, CA, and browser home/
httplogger init

# Start proxy + browser
httplogger launch

# Or proxy only (prints manual browser commands)
httplogger proxy
```

On first run, missing files are created automatically (`config.yml`, `ca-key.pem`, `ca.pem`, `home/`).

## Commands

```
httplogger init [--force]
httplogger proxy [--key PATH]
httplogger launch [--key PATH] [NAME|PATH] [--] [browser args...]
```

- **`init`** — write default `config.yml`, generate the CA, set up browser trust stores under `home/`.
- **`proxy`** — start the MITM proxy; print example launch commands for installed browsers.
- **`launch`** — start the proxy and open a browser. Optional browser name or path; extra browser flags only after `--`.

Examples:

```bash
httplogger launch firefox
httplogger launch /usr/bin/chromium -- --new-window
httplogger launch --key ./custom-ca-key.pem brave
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
