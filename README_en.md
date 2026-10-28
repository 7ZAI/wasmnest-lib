# wasmnest-lib

**The WasmNest capability repo (application-agnostic engines)**: of the four repositories (platform / capability / applications / testing), this is the only one dedicated to **reusable mechanisms + port abstractions + contracts**. It never reads platform or application source and makes no product decisions; it only provides plugin mechanisms and capability-domain engines that any host (desktop / mobile / headless) can depend on directly.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-DEA584?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![WebAssembly](https://img.shields.io/badge/WebAssembly-Component-654FF0?logo=webassembly&logoColor=white)](https://component-model.bytecodealliance.org)
[![Status](https://img.shields.io/badge/status-alpha-orange)](#9-project-status)

English | [简体中文](README.md)

> This README is a **navigation-oriented introduction**, not a development specification. Hard constraints, boundary locks and task routing are defined by [AGENTS.md](./AGENTS.md) and each crate's source of truth (`Cargo.toml` description, `src/lib.rs` header comments, WIT). When prose conflicts with reality, the source of truth and executable locks win.

## 1. Project Shape

- **No root workspace**: 17 independent crates (each with its own `Cargo.toml` and tracked `Cargo.lock`) plus 4 fixture crates. All commands run inside a crate directory; there is no repository-level `cargo test`.
- **Version line**: every crate restarts at `0.0.1`; the contract version `wasmnest:plugin@0.0.2` has a single handwritten source of truth in `wasmnest-contract`.
- **Consumption**: the platform's two hosts and the test repo depend on this working tree directly through sibling paths (no copies, no registry publication). The only exception is `wasmnest-wasm-core`'s `desktop-assembly` dependency on the published desktop SDK `wasmnest-plugin-api`, which consumers redirect back to the SDK working tree with `[patch.crates-io]`.

## 2. Dependency Layering

Capability crates default to **pure engine mechanisms + port abstractions** (zero WIT / zero SDK / zero host dependencies), so any host can depend on them. Only the `common-host` feature adds the WIT binding layer. Dependencies point downward; horizontal edges are pinned by each crate's `dependency_direction_lock.rs` / `boundary_lock.rs`:

```text
apps (wasm-apps / third party)
   │  WIT host-* · bus · events · inter-app calls
   ▼
capability-domain crates (default = pure engine + ports; common-host adds WIT bindings)
   ▼
wasmnest-host-kit (assembly time: state / module contracts / registry)
   ▼
wasmnest-wasm-core (runtime: runtime shell + core bindings + host_api adapters)
   ▼
desktop / mobile host src-tauri/src/ (composition root · thin shell) — platform repo
```

## 3. Crates at a Glance

| Directory (package) | Positioning (one line) | Shape / features | WIT source | Main consumers |
| --- | --- | --- | --- | --- |
| `wasmnest-contract` | **Contract constants**: the single handwritten source of `PACKAGE` / `PACKAGE_NAME` / `PACKAGE_VERSION`; zero dependencies, no WIT | no features | — | wasm-core (derives after `use`), platform scripts and locks (read the source with regexes) |
| `wasmnest-wasm-core` | Complete plugin mechanism: wasmtime component host runtime shell + host_api adapters + security gates + main library / engine face | `default = ["desktop-assembly"]`; `test-support` | `wit/core.wit` | platform hosts (desktop on by default / mobile with `default-features = false`), test repo |
| `wasmnest-host-kit` | Assembly-time mechanism core: `WasmPluginState` / `HostModule` contracts / automatic registry / limits / metrics | no features | — | both hosts, every `common-host` domain, wasm-core |
| `wasmnest-host-api-core` | host_api **implementation layer** for WIT-free domains: gate / storage / bus / database / log / events / fs | no features | — | wasm-core adapters, server-base (re-export guard constants) |
| `wasmnest-server-base` | server **leaf foundation**: error envelope / constants / system info / network config shapes / connection identity / port traits / wire | `tauri-compat` (on by default) | — | almost the whole repo + both hosts + test repo |
| `wasmnest-server-core` | Transport-agnostic server core: supervisor / filter chain / link_crypto / metrics / `TransportFace` + serve | no features | — | platform assembly, http/ws depend downward, test repo |
| `wasmnest-server-http` | HTTP transport + `host-http` binding layer (endpoint registry / gateway / middleware / DTO anchors) | `default = []`; `common-host` | `wit/http.wit` | desktop host (common-host), wasm-core (engine face), mobile host (engine face), test repo |
| `wasmnest-server-websocket` | WebSocket transport + `host-websocket` client-domain wiring / server-side engine functions | same as above | `wit/ws.wit` (shared with ws-client-engine) | same as http |
| `wasmnest-server-peer-net` | Peer-to-peer **engine domain** (incl. base mechanisms in `base/`: identity/TLS/trust/mDNS registration/transfer-session primitives — absorbed from the former `wasmnest-peer-net`) + `host-peer` binding layer (not a transport; does not join the actix composition) | same as above | `wit/peer.wit` | desktop (common-host), mobile (engine face), wasm-core (`PeerCtx`), test repo |
| `wasmnest-discovery-engine` | mDNS capability domain: shared daemon + type hub + browse/advertise handle tables + host advertiser face | same as above | `wit/mdns.wit` | desktop (common-host), mobile (engine face), test repo |
| `wasmnest-pty-engine` | PTY capability domain + cross-platform pseudo-terminal engine (process lifecycle / reader thread / ring buffer) | same as above | `wit/pty.wit` | desktop host (common-host) |
| `wasmnest-ws-client-engine` | WS **outbound client** domain: handle table / two tasks / heartbeat / backoff reconnect / reclaim on disable | no features | `wit/ws.wit` (shared contract source) | mobile host, test repo |
| `wasmnest-crypto-engine` | Neutral cryptographic primitives (aes_gcm/chacha/hybrid/kdf/rsa/x25519) + name-addressed registry | no features | — (WIT face lives in host `plugin/crypto.rs`) | desktop host, server-core |
| `wasmnest-notify-engine` | Notification **contract room**: holds only WIT + port vocabulary (currently no ports), zero implementation | no features | `wit/notify.wit` | both hosts' `compose.json` — **no Rust consumer** |
| `link-crypto` (`wasmnest-link-crypto`) | Link-message encryption protocol core: HTTP envelope / WS handshake IKM / binary frames | no features | — | wasm-core (`link_crypto`), both hosts |
| `wasmnest-headless-host-probe` | Headless-host probe: references every capability domain in non-desktop form, proving "default shape is consumable by any host" | no features (never enables `common-host`), zero dev-deps | — | gate only — **must not enter any host dependency list** |

> The only directory name that differs from its package name is `link-crypto` (package `wasmnest-link-crypto`).

## 4. Group Details

### 4.1 Contracts and the Plugin-Mechanism Trio

- **`wasmnest-contract`**: the single handwritten source of contract constants. `PACKAGE_NAME` / `PACKAGE_VERSION` / `PACKAGE` must keep the exact shape `pub const <NAME>: &str = "<value>";` (including `: &str`, no macro, no `env!` / `concat!`) — two Node parsers in the platform repo read this shape, making it a cross-language textual contract.
- **`wasmnest-host-kit` (assembly time)**: mechanisms only — instance state (including WASI slots, always compiled), `HostModule` contracts, automatic registry (collect → order → allowlist → linker assembly), lifecycle hooks, port assembly self-report, routing vocabulary, limits / metrics. No product nouns are allowed in this crate.
- **`wasmnest-host-api-core` (runtime implementation layer)**: mechanism semantics for host_api domains that do not depend on WIT bindgen traits or end-specific types. Each domain has two layers: implementation (this crate) plus per-end adapters (in wasm-core or the host). `config` / `http` have been judged **not to extract**; do not unify them casually.
- **`wasmnest-wasm-core` (runtime whole core, single shape)**: the plugin-system microkernel — `manager/` (loading / lifecycle / instance calls / tasks / hot reload), `manager/runtime/` (unified runtime shell + the **only legal core binding** `core_binding.rs`), `host_api/` (adapters), `security/`, `db/`, `system/`. There is no common/bare split: end differences are injected through `HostModule` self-report, `GuestEventDispatcher`, `AbiPolicy` / `HostFactsPort`. `desktop-assembly` (on by default) is the desktop-only assembly surface; the mobile host disables it with `default-features = false`. `test-support` is the test surface.

### 4.2 Capability-domain Engines (five crates with `common-host`)

Default shape = **pure engine mechanisms + port abstractions**, with zero WIT / SDK / wasmtime. `common-host` adds `bindgen!` / `HostModule` self-report / `inventory::submit!` / `impl Host`. Enabling the feature changes no ABI, WIT, permission bits, event shapes or registration. Platform differences are injected through port traits (permission gate / event delivery / background tasks / paths / system info, etc.); **missing ports fail visibly**.

- **`wasmnest-server-http`**: HTTP transport + `host-http` binding layer (2 inbound + 1 outbound primitive).
- **`wasmnest-server-websocket`**: WebSocket transport (connection skeleton / plugin endpoint channels / registry / graceful shutdown) + `host-websocket` binding layer.
- **`wasmnest-server-peer-net`**: the peer-to-peer **engine domain**, not a transport — it does not join the actix composition, filter chain or link encryption. mDNS handles are injected as plain values through `MdnsPort` (single-listener invariant). Product business (transfer tasks / policies / history / shared roots / browsing orchestration) lives in apps-repo plugins; this crate keeps only engine primitives and lifecycle, plus the base mechanisms (absorbed from `wasmnest-peer-net` in 2026-10-22: identity/TLS/trust/mDNS registration/transfer-session primitives) as its own `base/` submodule.
- **`wasmnest-discovery-engine`**: mDNS capability domain. The process-wide shared daemon may only be created once, in `engine.rs`; for a given service type only `type_hub.rs` may call `daemon.browse` / `stop_browse` (a duplicate browse silently kills other event streams).
- **`wasmnest-pty-engine`**: PTY capability domain (`host-pty` 6 primitives) plus the plugin-private pseudo-terminal engine face. The engine face is cross-platform and wasm-free; it accepts only caller-computed argv and does no shell wrapping; output goes through a ring buffer with watermark notifications.

### 4.3 Server Layering (`base` / `core` / transports)

- **`wasmnest-server-base`** is the leaf foundation: `tauri-compat` is on by default solely for one `From<tauri::Error> for AppError` impl; non-Tauri consumers use `default-features = false` and pay for explicit `map_err` at boundaries. Changing its dependency surface affects the whole repo (including the headless host).
- **`wasmnest-server-core`** is transport-agnostic: supervisor / filter chain / link_crypto / metrics / `TransportFace` + serve, with dependency inversion. http / ws depend only downward on it, have zero horizontal imports between them, and must not know about hosts.
- The transport crates (http / websocket) are the only layer allowed to use actix.

### 4.4 Foundations, Independent Domains and the Contract Room

- **Peer-to-peer base mechanisms** (absorbed from the former `wasmnest-peer-net` crate into `wasmnest-server-peer-net`'s `base/` in the 2026-10-22 dissolve): reinstalling means a new identity (deliberately separate from device identity); certificate public key = node public key, fingerprint = identity (`node_id = hex(SHA-256(raw ed25519 key))`); untrusted inbound connections stop at an application-layer confirmation gate; `_wasmnest-peer._tcp.local.` is completely independent of the legacy terminal link service `_wasmnest._tcp`.
- **`link-crypto`**: link-message encryption protocol core, pure byte protocol only. Constants and algorithms are a compatibility surface and must match the mobile TypeScript implementation byte for byte — changing a constant is a cross-end breaking change.
- **`wasmnest-ws-client-engine`**: WS outbound client domain (`host-websocket` client subset, 5 primitives + reclaim on disable). Platform differences (permission gate / delivery / background tasks / jwt issuance / backoff) are injected through `WsClientPorts`; the production dependency list contains zero internal crates.
- **`wasmnest-crypto-engine`**: exposes only neutral algorithm primitives with no business semantics; no authentication orchestration, negotiation or key policy; key material is always supplied by the caller, and host identity keys are never touched.
- **`wasmnest-notify-engine`**: contract room holding only `wit/notify.wit`, zero implementation. Unsupported platform capabilities (such as no vibration on desktop) are documented as silently ignored; implementations must not turn that into an error.

### 4.5 Gate Probe

- **`wasmnest-headless-host-probe`**: headless-host probe, pinning "capability domains in default shape are consumable by any host with zero WIT / zero desktop SDK dependencies". It never enables `common-host`, has zero dev-deps, and fails the gate if `cargo tree` shows `wasmtime` / `wit-bindgen` / `inventory` / `wasmnest-host-kit` / `wasmnest-plugin-api`. It must not enter any host dependency list and is not registered in `SPLIT_CRATES`.

## 5. Fixture Crates (not in the list above, not published)

- `wasmnest-host-kit/fixtures/forced-link-probe`: forced-link proof — link-time attributes cannot be both "present" and "absent" in one process, so it maps to two independent test binaries (`forced_link` / `forced_link_absent`).
- `wasmnest-wasm-core/fixtures/{wasi-test,wasip3-test,p3-async-host-import-test}`: self-contained WASI / WASI p3 / async host-import fixtures bound to this crate's `wit/core.wit`, with zero SDK dependencies.

## 6. Four-repo Collaboration

This repo is the **mechanism source of truth** for the four repositories: the platform's two hosts consume it directly through Cargo sibling paths, the test repo reads the same physical path (so the dependency graph contains exactly one copy and type identity holds), and apps use capabilities only through the platform SDKs.

```text
wasmnest/        platform: dual-end hosts + per-end SDKs + build / release tooling
wasmnest-lib/    capability (this repo): application-agnostic engines + ports + WIT sources
wasmnest-apps/   applications: all business wasm apps
wasmnest-test/   testing: real cross-end interop + cross-repo contract locks
```

| Repository | Relationship to this repo |
| --- | --- |
| [wasmnest](https://github.com/7ZAI/wasmnest) | Depends directly via `../../../wasmnest-lib/<crate>`; versions pinned by `repos.lib.tag` in the platform's `release-manifest.json` |
| [wasmnest-lib](https://github.com/7ZAI/wasmnest-lib) (this repo) | Never reads platform / app source; single source of truth for contracts and mechanisms |
| [wasmnest-apps](https://github.com/7ZAI/wasmnest-apps) | Never depends on this repo directly; apps use platform SDKs, and these mechanisms take effect through host assembly |
| [wasmnest-test](https://github.com/7ZAI/wasmnest-test) | References this repo and both hosts through sibling paths to run real interop and cross-repo locks |

The platform does not copy, mirror or submodule this repo. The default location is the sibling `../wasmnest-lib`; `WASMNEST_LIB_ROOT` overrides it (Node resolver = platform `scripts/lib-paths.mjs`, test repo = `tests/common/repo_paths.rs::lib_root()`).

## 7. Quick Verification

This repo has **no root workspace**; commands always run inside a crate:

```bash
cd wasmnest-wasm-core && cargo test
cd ../wasmnest-host-kit && cargo test
cd ../wasmnest-headless-host-probe && cargo test
```

- The root `.cargo/config.toml` forces `rustc-wrapper = "sccache"`; without it cargo fails immediately. This is intentional; do not bypass it.
- `jobs = 4` is a memory fallback; override it with `CARGO_BUILD_JOBS` when memory allows. **Never set `CARGO_INCREMENTAL=1`**, because sccache refuses to run.
- Cross-repo contracts and real interop are verified in the test repo's `cross-end-tests` (wire / permission-vocabulary / mDNS locks + cross-end scenarios).

## 8. Pointers

| Need | Entry point |
| --- | --- |
| Development navigation and hard constraints | [AGENTS.md](./AGENTS.md) |
| Contract package name / version source | `wasmnest-contract/src/lib.rs` |
| Core / domain WIT | `wasmnest-wasm-core/wit/core.wit` and each domain's `wit/<domain>.wit` (mdns / pty / http / peer / ws / notify) |
| Permission vocabulary source | `wasmnest-wasm-core/src/permission.rs` |
| Main database schema | `wasmnest-wasm-core/src/db/schema.sql` |
| Cross-repo locks (wire / permissions / mDNS) | Test repo `cross-end-tests/tests/{wire_drift_locks,permission_vocabulary_lock,mdns_browse_singleton_lock}.rs` |
| Platform governance locks | Platform repo's both `src-tauri/tests/` (shape / semantics / whole-core / purity locks) |
| Shared conventions across the four repos | Platform repo `docs/public/{git,commenting,testing,versioning,issues}.md` |

## 9. Project Status

- Early development, version line `0.0.1`; no external ABI compatibility obligations, so breaking changes are allowed directly, while cross-repo contracts are pinned by exact tags.
- This repo has its own tag line `lib-vX.Y.Z`; releases are pinned by the platform's `release-manifest.json` together with the contract version and WIT fingerprint.
- Versions and tags are bumped only for releases; day-to-day development does not bump.

## 10. License

[MIT](LICENSE) © 2026 7ZAI
