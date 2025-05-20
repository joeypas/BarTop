# BarTop
A minimal DNS library & stub/recursive resolver

![Zig](https://img.shields.io/badge/Zig-%23F7A41D.svg?style=flat-square&logo=zig&logoColor=white)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE-MIT)
## What is BarTop?
BarTop is an educational DNS toolkit written in **Zig**.  
It includes

* **`dns.zig`** - a Wire-format encoder/decoder able to read & write common RR types (A, AAAA, NS, CNAME, MX, PTR, TXT, SOA, …)  
* **`zone.zig`** - a reader for RFC 1035 master files supporting `$ORIGIN` / `$TTL` and incremental state tracking 
* **`src/client.zig`** - a dns client CLI that crafts a query, sends it over UDP, and prints the decoded answer
* **`src/stub_resolver.zig`** - an experimental stub resolver built on [`libxev`](https://github.com/mitchellh/libxev) with an in-memory LRU cache 
* **Utilities**  
  * `util/lru.zig` (cache) and `util/queue.zig`  
  * Simple build script + `build.zig.zon` dependency list (libxev, zig-clap)

> **Status:** personal project, API in flux, not production-ready.

---
## API Reference

Automatically generated API Reference for the project can be found at
https://joeypas.github.io/BarTop. Note that Zig autodoc is in beta; the website
may be broken or incomplete.

## Quick start

BarTop targets **Zig 0.14**   

```bash
git clone https://github.com/joeypas/BarTop.git
cd BarTop
zig build          # Debug mode contains logs, ReleaseFast doesn't
