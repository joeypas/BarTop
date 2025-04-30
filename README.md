# BarTop · A minimal DNS library & stub/recursive resolver in Zig

BarTop is an educational DNS toolkit written in **Zig**.  
It includes

* **`dns.zig`** - a Wire-format encoder/decoder able to read & write common RR types (A, AAAA, NS, CNAME, MX, PTR, TXT, SOA, …)  
* **`zone.zig`** - a reader for RFC 1035 master files supporting `$ORIGIN` / `$TTL` and incremental state tracking 
* **`src/client.zig`** - a dns client CLI that crafts a query, sends it over UDP, and prints the decoded answer
* **`src/server.zig`** - an experimental stub resolver built on [`libxev`](https://github.com/mitchellh/libxev) with an in-memory LRU cache 
* **Utilities**  
  * `util/lru.zig` (cache) and `util/queue.zig`  
  * Simple build script + `build.zig.zon` dependency list (libxev, zig-clap)

> **Status:** personal project, API in flux, not production-ready.

---

## Quick start

BarTop targets **Zig 0.14**   

### 2 · Fetch dependencies

```bash
git clone https://github.com/joeypas/BarTop.git
cd BarTop
zig build          # Debug mode contains logs, ReleaseFast doesn't
