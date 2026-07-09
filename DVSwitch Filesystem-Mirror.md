# DVSwitch Filesystem-Mirror

## Purpose

This repository is a **filesystem-mirror** — a pure representation of the
DVSwitch package contents as they would appear on a Debian Linux filesystem.

Unlike traditional packaging repositories that carry debian packaging metadata
(`DEBIAN/`, control files, maintainer scripts), this repository strips all
packaging metadata and maps directly to the target filesystem paths.

## Structure

Every file is placed at its intended target path, rooted at the repository root:

```
etc/          → /etc/          (configuration files, logrotate configs)
lib/          → /lib/          (systemd service units)
opt/          → /opt/          (binaries, application data)
usr/          → /usr/          (scripts, libraries, shared data)
var/          → /var/          (runtime data, language files, talkgroup lists)
```

## Architecture-Specific Binaries

Architecture-specific ELF binaries follow a `.arch` suffix convention:

- `foo.amd64` — x86_64
- `foo.arm64` — aarch64
- `foo.armhf` — ARM hard-float
- `foo.i386` — x86

The **amd64** variant is authoritative for configuration and data files;
other architectures contribute only architecture-specific ELF binaries.

## Branches

| Branch | Purpose |
|--------|---------|
| `bookworm` | Filesystem-mirror for Debian 12 bookworm |
| `development` | Development branch (tracks bookworm) |

## Origin

Binaries and configuration files in this repository were extracted from
Debian `.deb` packages built by [DVSwitch](https://github.com/DVSwitch).
