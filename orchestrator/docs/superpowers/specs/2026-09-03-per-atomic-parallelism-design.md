# Per-Atomic Parallelism Design

**Date:** 2026-09-03
**Author:** Audspect Research
**Status:** Design Phase
**Scope:** Per-atomic resource declaration replacing per-technique `ResourceProfile`
**Non-goals:** sandboxed/isolated execution, intention (multi-granularity) locks, an `ISOLATABLE` state

---

## Core invariant

> **A profile may cause unnecessary serialization, but an under-declared profile must never permit conflicting execution.**

Everything below exists to make that statement mechanically true. Where a choice trades throughput for safety, this spec takes safety and says so at the point of the trade.

---

## Motivation

`sched.Run` already runs steps concurrently across `NumCPU` (capped 16) workers, with a
deadlock-free lock manager and a parallel-vs-serial equivalence test. The machinery is sound and
shipped.

It is starved of input. `ResourceProfileFor` (`orchestrator/internal/scenario/resource.go`) returns a
profile for **~15 Discovery techniques**; every other technique resolves to `nil`, which
`resolve()` turns into an exclusive global lock — fully serial. On a 398-step sweep, 16 workers sit
almost entirely idle.

An earlier investigation searched Defense-Evasion, Collection and Reconnaissance for further
parallel-safe *techniques* and found none: structurally, the Discovery tactic already *is* the
observational bucket. The technique-level well is dry.

The remaining headroom is **granularity**. A technique bundles several atomics, and one destructive
atomic currently forces all of its siblings serial even when those siblings are harmless reads.
Moving the declaration from technique to atomic unlocks those siblings without touching the
destructive one.

**This is not agent work.** `ResourceProfileFor` lives server-side, so the benefit lands identically
on Windows, Linux and macOS.

### Explicitly not the motivation

A POSIX host pool was considered first and rejected on measurement. Process spawn through the
agent's exact execution path costs **p50 3.67 ms / mean 3.90 ms** on Linux (300 samples), against
the 300–700 ms PowerShell cold start that justifies the Windows pool. Across 398 steps that is
~1.6 s of total overhead — noise against a sweep measured in minutes. Serialization, not spawn
cost, is the Linux bottleneck.

---

## The audit boundary

The single most important structural property of this design:

```
evidence  →  resource declaration  →  canonicalisation  →  lock acquisition  →  execution
   ▲                                                              ▲
   │                                                              │
 human proves what the atomic                    scheduler mechanically converts
 actually touches, from resolved                 a declaration into locks. It NEVER
 command text + platform semantics               decides whether the declaration was
                                                 truthful.
```

The scheduler stays dumb by construction. All judgement lives upstream in the profile, backed by
evidence. This preserves `sched`'s existing contract, quoted from its package doc:

> Safety is enforced by execution constraints — resource locks acquired in a canonical order — NOT
> by trusting a step's classification. Labels can therefore only make execution faster, never less
> accurate.

**Parallelism is never stored.** There is no `parallel_safe` field. Concurrency is derived entirely
from resolved lock conflicts. A flat `PARALLEL`/`SERIAL` enum would discard exactly the information
the lock manager needs — two atomics both marked "parallel" still conflict if one writes what the
other reads.

---

## Schema

### Replaces

```go
type ResourceProfile struct {
    Domains []ResourceLock
    Scope   string   // "local" | "global"
    Risk    string   // "observation" | "modification" | "persistence"
}
```

`Risk` is a **single value for the whole profile**, so an atomic that reads `process` and writes
`filesystem` cannot be expressed. `observation` under-locks the write (unsafe); `modification`
over-locks the read (safe, needlessly serial). At technique granularity this rarely bites because
whole techniques skew one way. At atomic granularity it bites constantly — a large share of atomics
read a config and write a temp artifact.

### With

```go
// AtomicProfile declares the resources one atomic touches. Direction is per
// resource, not per profile.
type AtomicProfile struct {
    Reads  []Resource `json:"reads,omitempty"`
    Writes []Resource `json:"writes,omitempty"`

    // ObservesFootprint marks an atomic whose EVIDENCE observes the surface that
    // BAS's own execution perturbs (process table, auth log, dmesg, temp dirs).
    // See "The basFootprint quiescence barrier" — the lock polarity is inverted
    // from ordinary reads and must not be "simplified" back.
    ObservesFootprint bool `json:"observesFootprint,omitempty"`
}

// Resource names one resource. An empty Key means the WHOLE domain.
type Resource struct {
    Domain string `json:"domain"`
    Key    string `json:"key,omitempty"`
}
```

`Risk` and `Scope` disappear as execution primitives. If existing call sites need them during
migration they may be retained as derived, read-only compatibility fields, but nothing in
`resolve()` may consult them.

**Absent profile → whole-world exclusive.** Unchanged, and load-bearing: a nil profile, an empty
declaration, or anything unrecognised resolves to the exclusive global barrier. Unknown is never
optimistically treated as safe.

---

## Resource identity

### Two levels, and no more

```
domain root :  <domain>          — the barrier for the whole domain
leaf        :  <domain>/<key>    — one opaque, canonical identifier within it
```

**Arbitrary hierarchy is deliberately excluded from v1.** It cannot be made safe on
`sync.RWMutex`, and pretending otherwise creates precisely the illusion of precision this design is
trying to avoid.

The failing case:

```
A:  reads  filesystem:/etc                    (enumerate the config tree)
B:  writes filesystem:/etc/ssh/sshd_config
```

Under ancestor expansion with ancestors held shared, both hold shared on `/etc`, so they run
concurrently and **A's evidence is silently contaminated by B**. Under-declaration was not the
failure — the lock algebra was.

Fixing this correctly requires multi-granularity locking with intention modes (`IS`/`IX`/`S`/`X`),
where `S` on `/etc` conflicts with `IX` on `/etc`. `RWMutex` offers two modes and collapses `IS` and
`IX` into one, so it structurally cannot express the conflict. Building an intention-lock manager is
a larger change than the profile work and carries its own deadlock-ordering burden. **Deferred, not
solved.**

### Resolution rules

| declaration | locks acquired |
|---|---|
| keyed read `d/k` | `shared` on `d` (root), `shared` on `d/k` |
| keyed write `d/k` | `shared` on `d` (root), `exclusive` on `d/k` |
| whole-domain read `d` (empty key) | **`exclusive` on `d`** |
| whole-domain write `d` (empty key) | `exclusive` on `d` |

The third row is the one to read twice. *"I read this entire domain"* means *"nothing may modify
anything within it"*, which is an exclusive hold on the root. The cost is that two whole-domain
readers serialize against each other unnecessarily. That is squarely inside the core invariant:
unnecessary serialization is permitted; unsafe concurrency is not.

**Writes dominate reads for the same resource.** An atomic declaring both a read and a write of the
same canonical resource acquires one **exclusive** hold, not a shared and an exclusive hold.
`resolve()` already implements this (`writes[k] = writes[k] || exclusive`); the behaviour is
retained and becomes a stated contract rather than an implementation detail.

### Required change to `resolve()` — the root lock is new

Today `resolve()` builds a single lock key per declared resource:

```go
k := d.Domain
if d.Key != "" { k += "/" + d.Key }
```

So `filesystem` (whole domain) and `filesystem//tmp/a` (keyed) are **different keys that do not
conflict**. A step declaring a whole-domain read would run concurrently with a step declaring a
keyed write inside it.

**This hole is latent rather than live**: every profile shipped today uses `observe(domain)`, which
sets no `Key`, so all current locks are whole-domain and the case never arises. **It becomes live the
moment keyed per-atomic profiles are introduced** — which is the entire point of this design.

Therefore keyed access must additionally take a **shared hold on the bare domain root**, which is
what makes a whole-domain exclusive hold conflict with every keyed access beneath it. This is a
prerequisite change, not an optimisation, and it must land before or with the first keyed profile.

Canonicalisation also owns the key-joining form, so that a domain and a key whose leading separator
would otherwise produce `filesystem//tmp/a` yield one stable spelling.

### Worked cases

| pair | resolution | outcome |
|---|---|---|
| write `fs:/tmp/a` vs write `fs:/tmp/b` | shared root; distinct exclusive leaves | concurrent |
| read `fs:/tmp/a` vs write `fs:/tmp/a` | conflict at leaf | serial |
| read whole `fs` vs write `fs:/tmp/a` | exclusive root vs shared root | serial |
| write whole `fs` vs anything in `fs` | exclusive root | serial |
| read `svc:sshd` vs read `svc:sshd` | shared/shared at leaf | concurrent |
| read `svc:sshd` vs write `svc:sshd` | conflict at leaf | serial |

### Consequence to enforce in review

**A subtree is not expressible as a narrow key.** An atomic reading or writing a whole tree declares
the **domain with an empty key**. Declaring `filesystem:/etc` to mean "the /etc subtree" would read
as narrow, lock as narrow, and mean broad — the exact failure mode this section exists to prevent.

---

## Canonicalisation

Resource identity is `(domain, canonical key)`. **Canonicalisation is domain-specific**; a single
global path normaliser would be wrong.

| domain family | rules |
|---|---|
| path-like (`filesystem`) | absolute only; `filepath.Clean`; no trailing slash; **reject** relative paths and any `..` rather than cleaning them (a relative path has no stable identity); case-sensitive on POSIX, case-folded on Windows |
| `registry` | case-folded; hive aliases normalised (`HKLM` ≡ `HKEY_LOCAL_MACHINE`); `WOW6432Node` views are **distinct** resources |
| flat identifiers (`service`, `port`, `user`, `task`, `process`) | opaque tokens with per-domain form — `port` as `tcp/4444`; `service` case-folded on Windows, case-sensitive on POSIX |

Each domain supplies `canonicalise(key) (string, ok)`.

**Failure degrades, never passes through.** Where `ok` is false — an unexpanded `%TEMP%` or `$HOME`,
a relative path, an unparseable form — the key **degrades to empty**, i.e. the whole-domain
exclusive lock. A key that cannot be canonicalised is never accepted as written.

### Enforcement point

Canonicalisation and degradation run **in the agent, at the lock-manager boundary** — not only
server-side where profiles are authored.

Profiles arrive over the wire from a server that may be a different version. If the agent trusts a
key it cannot parse, the core invariant becomes a property of version alignment rather than of the
enforcement point. Validating locally keeps *"under-declaration can never permit conflicting
execution"* true locally, which is the only place it can be relied on.

---

## The basFootprint quiescence barrier

### The problem

Every atomic, simply by running, perturbs the surface some other atomics observe:

- it appears in the **process table**
- it writes **temp files**
- its `sudo`/auth activity appears in **auth logs**
- it may emit **kernel messages** visible to `dmesg`

Declared honestly as ordinary writes, nothing would ever be parallel. So the model needs an explicit
exemption for BAS's own execution footprint — and that exemption is exactly what makes
footprint-observing atomics evidence-unsafe.

`T1057` (Process Discovery) is currently shipped as `observe(domProcess)`, i.e. parallel-safe. Under
concurrency `ps aux` returns BAS's own atomics. **This is a bug in the existing model**, not
evidence that the new model is too conservative.

### The mechanism

The footprint is **not** declared in profile text. It is a scheduler-enforced implicit lock:

```
declared resources
        +
execution footprint (implicit)
        ↓
     resolve()
        ↓
     lock set
```

This preserves the semantic distinction:

- **declared domains** = what the atomic intentionally touches
- **basFootprint** = the fact that execution itself perturbs the observation surface

### The polarity — do not "simplify" this

| role | intent | lock mode |
|---|---|---|
| every executing atomic | *"I am perturbing the surface"* | **shared** |
| footprint observer (`ObservesFootprint: true`) | *"I require the surface quiet"* | **exclusive** |

This is the **inverted-lock idiom** and it is the opposite of the intuitive mapping. Perturbers must
be compatible with one another (shared/shared) or no two atomics could ever overlap; the observer
must exclude all of them (exclusive).

> **Warning for future maintainers.** Modelling this as an ordinary read/write — "everyone *writes*
> the footprint, the observer *reads* it" — inverts both modes: every atomic would take an exclusive
> hold, every pair would conflict, and the entire parallelism feature would be silently disabled
> while appearing correct. The barrier is named by intent (`perturbs` / `observes`) rather than
> read/write for exactly this reason.

### Resolution

- every step: `shared` on `basFootprint`
- `ObservesFootprint: true`: `exclusive` on `basFootprint` (replacing the shared hold)

Known observers to reclassify: `T1057` (Process Discovery), auth-log readers, `dmesg` readers, and
any atomic enumerating a shared temp directory.

---

## Evidence standard for authoring a profile

The author proves, **from the resolved command text for that atomic on that platform** — not from
the technique's description — what the atomic touches. Absence of evidence means the whole-world
exclusive lock, never "probably safe".

| property | evidence required |
|---|---|
| every read enumerated | each resource the command inspects is named, with a canonical key or the bare domain |
| every write enumerated | each resource the command creates, deletes, modifies, enables or disables is named |
| no implicit side effects | command semantics do not trigger writes or actions beyond those declared |
| no fixed shared artifact | no fixed temp path, fixed port, or other singleton that a sibling atomic could collide on — or, if present, it is declared as a narrow key so the collision serializes |
| footprint dependence stated | if the evidence observes the process table, auth log, `dmesg`, or a shared temp dir, `ObservesFootprint` is set |
| no ordering dependency | the result does not require another atomic's state transition, and running it early does not change another atomic's precondition |

### Borderline cases the standard must catch

1. **Reads that act.** `systemctl status X` is pure; SysV `service X status` starts the unit on some
   distros. `find -exec`. `ss -K`. `journalctl --vacuum-*`. Anything with `--repair`, `--sync`,
   `--fix`.
2. **Fixed shared artifacts.** Two atomics writing `/tmp/T1234.txt`, or both binding `tcp/4444`. The
   loser fails with plausible error text — and `blockSignature` matches `"permission denied"`,
   `"access denied"`, `"blocked by"`. **A concurrency artifact then scores as PASS, a control
   success.** This is the same failure class as the timed-out-step bug fixed in `32e42cc`, and it
   makes parallelism widening a scoring-integrity change, not merely a performance one.
3. **Ambient accumulators.** `last`, `lastb`, `dmesg`, `/var/log/auth.log` — perturbed by any atomic
   that authenticates, `sudo`s, or triggers a kernel message. Same shape as the footprint problem.
4. **Load-sensitive verdicts.** An atomic whose result depends on timing becomes nondeterministic
   under parallel load. Target-safe, evidence-safe, still wrong. Declare serial.
5. **Aliasing.** Symlinks, hardlinks and bind mounts defeat key identity — `/etc/foo` and
   `/var/lib/x/foo` may be the same inode, and that is a property of the target host at execution
   time, unknowable when the profile is authored. **Rule: atomics touching symlink-prone areas
   declare the domain, not a key.** Coarser, provably safe, and stated rather than assumed.

---

## Migration

1. `AtomicProfile` lands alongside the existing per-technique `ResourceProfile`; `resolve()` accepts
   either. Unprofiled atomics inherit their technique's profile, so behaviour is unchanged on day
   one.
2. `basFootprint` is introduced with every step taking the shared hold. Because shared holds are
   mutually compatible, this is a no-op for existing scheduling.
3. `T1057` and the other footprint observers are marked `ObservesFootprint`. This **removes**
   parallelism that exists today — correctly.
4. Atomics are profiled incrementally, evidence-first. Each addition can only widen parallelism, per
   the `sched` contract, so partial coverage is always safe.

No step of this migration can make execution less correct than it is today.

---

## Testing

- **Equivalence.** Extend the existing parallel-vs-serial equivalence test to per-atomic profiles:
  outcomes under `workers=N` must equal `workers=1` for a generated world of profiles.
- **Lock algebra.** Table-driven over the worked cases above, asserting conflict/no-conflict for each
  pair — including the whole-domain-read case, which is the counter-intuitive one.
- **Canonicalisation.** Per domain: equivalent spellings map to one key; relative paths, `..`, and
  unexpanded variables degrade to the empty key rather than being accepted.
- **Degradation at the boundary.** A profile carrying an unparseable key, injected as if from a
  different server version, must resolve to whole-domain exclusive.
- **Footprint polarity.** Assert two ordinary atomics can overlap, and that an `ObservesFootprint`
  atomic overlaps with neither. This is the test that fails loudly if anyone re-derives the barrier
  as ordinary read/write semantics.
- **No stored parallelism.** Assert no field named `parallel`/`safe` exists on the profile, so the
  derived-only property cannot regress into a classification.

---

## Deferred

| item | reason |
|---|---|
| `ISOLATABLE` | On Linux, isolation means namespaces/containers. A BAS simulation usually asks *"did this endpoint's controls stop it"* — inside a namespace the host EDR may not observe the syscalls and the AppArmor profile may not apply, so the result becomes evidence about the sandbox, not the endpoint. The class is sound only for atomics asking *"does this work mechanically"*. Excluded until concrete, valid examples exist. |
| intention locks (`IS`/`IX`/`S`/`X`) | Required for genuine subtree semantics; larger than the profile work and a deadlock-ordering problem in its own right. Two-level identity is the safe subset. |
| symlink resolution | Would require a `stat` per declared key before every step, on the target host. Handled by the coarse-declaration rule instead. |
