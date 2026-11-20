# Resolver Architecture Map

## Top-Level Shape

| Module | Responsibility |
| --- | --- |
| `dns_server.zig` | UDP/TCP server plumbing only |
| `resolver.zig` | Client request handling, cache lookup, fetch attach/start |
| `fetch_manager.zig` | Active fetch deduplication and lifecycle |
| `fetch.zig` | One recursive resolution state machine |
| `dns_cache.zig` | RRset cache, negative cache, delegation cache |
| `transport.zig` | UDP/TCP upstream query engine |
| `response_builder.zig` | Builds client responses from cache/fetch results |

## Core Objects

```zig
const Resolver = struct {
    cache: DnsCache,
    fetches: FetchManager,
    transport: Transport,
    root_hints: Delegation,
    policy: ResolverPolicy,
};
```

```zig
const FetchManager = struct {
    active: HashMap(FetchKey, *Fetch),
    mutex: Io.Mutex,

    pub fn attachOrStart(self: *FetchManager, req: ClientRequest) !void;
};
```

```zig
const Fetch = struct {
    key: FetchKey,
    waiters: ArrayList(ClientRequest),
    state: FetchState,

    current_delegation: Delegation,
    depth: u8,
    query_count: u16,
    inflight: ArrayList(UpstreamQuery),
    tried: HashSet(ServerAddr),
};
```

```zig
const Delegation = struct {
    zone: Name,
    ns: RRSet,
    servers: []NameServer,
    expires_at: Instant,
};
```

```zig
const RRSet = struct {
    name: Name,
    type: Type,
    class: Class,
    records: []Record,
    ttl: u32,
    expires_at: Instant,
    trust: Trust,
};
```

## Request Flow

1. Server receives DNS packet.
2. Resolver parses request into `ClientRequest`.
3. Resolver checks exact answer cache.
4. If hit, `response_builder` sends response immediately.
5. If miss, resolver calls `fetches.attachOrStart(req)`.
6. If identical fetch exists, request becomes a waiter.
7. If not, create fetch and start the fetch state machine.
8. Fetch iterates upstream until answer, negative result, or failure.
9. Fetch writes cache updates.
10. Fetch builds one canonical result and sends it to all waiters.
11. Fetch removes itself from active map.

## Fetch State Machine

```text
start
  -> cache_exact_answer
  -> find_best_delegation
  -> query_nameservers
  -> process_response
      answer   -> complete_positive
      cname    -> follow_cname_or_complete_chain
      referral -> install_delegation_and_continue
      nxdomain -> complete_negative
      nodata   -> complete_negative
      error    -> retry_or_fail
  -> done
```

Referral processing should not require cache visibility. A referral response should produce a `Delegation` object immediately, and cache writes can happen separately.

## Cache Design

Use three caches:

1. `rrsets`

Key: `(name, type, class)`

Value: `RRSet`

Used for answers, CNAME, glue, and NS.

2. `delegations`

Key: `zone`

Value: `Delegation`

Used by `find_best_delegation`.

3. `negative`

Key: `(name, type, class)`

Value: `NegativeEntry`

Used for NXDOMAIN/NODATA.

This is simpler and faster than forcing all DNS concepts into one generic key/value map.

## Transport

Transport should be reusable and boring:

```zig
const Transport = struct {
    pub fn queryAny(
        self: *Transport,
        delegation: *const Delegation,
        question: Question,
        policy: QueryPolicy,
    ) !UpstreamResponse;
};
```

## Xev Context

- xev.Completion for send/recv
- timer completion
- packet buffer
- server addr
- parent Fetch pointer

Behavior:

- UDP first.
- Query 1-2 servers at once.
- Stop on first valid response.
- Retry limited fallback servers.
- TCP retry if UDP response has `TC=1`.
- Track RTT/failure stats per server.

## Response Builder

Keep this separate from cache and fetch logic.

It decides:

- header flags
- question section
- answer section
- whether to include authority/additional
- whether response is authoritative
- whether answer came from stale cache
- truncation if client buffer is small

That separation matters because cache storage and wire response shape are not the same problem.

## Policy Object

Put knobs in one place:

```zig
const ResolverPolicy = struct {
    max_depth: u8 = 16,
    max_queries_per_fetch: u16 = 50,
    max_inflight_upstreams: u8 = 2,
    max_waiters_per_fetch: usize = 128,
    max_active_fetches: usize = 4096,
    udp_payload_size: usize = 1232,
    upstream_timeout_ms: u64 = 2000,
    serve_stale: bool = false,
};
```

## What This Buys You

- Duplicate client queries collapse into one fetch.
- Cache semantics are DNS-native.
- Referrals are first-class state.
- Upstream query logic is isolated.
- Response formatting stops contaminating resolver/cache logic.
- TCP fallback and negative caching become straightforward additions.

## What I Would Build First

1. `DnsCache` with `RRSet`, `Delegation`, and `NegativeEntry`.
2. `Transport.queryAny`.
3. `Fetch` that resolves one qname/qtype.
4. `FetchManager` dedupe/waiters.
5. `Resolver.handlePacket` as thin glue.
6. `ResponseBuilder`.

That order gives you a working recursive resolver before you add more advanced behavior.

## Mental Model

```text
Resolver accepts client intent.
FetchManager deduplicates work.
Fetch performs recursion.
Transport talks upstream.
Cache stores DNS facts.
ResponseBuilder turns facts into packets.
```
