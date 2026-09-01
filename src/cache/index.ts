// A time-to-live cache. Permissions are checked on EVERY admin request (and
// the dashboard can fire off a dozen at once for a single screen), so
// without this every click would mean a full round of database queries.
//
// The clock is injectable so tests don't have to wait in real time.

type Entry<T> = { value: T; expiresAt: number }

export class TtlCache<T> {
  private readonly store = new Map<string, Entry<T>>()

  constructor(
    private readonly ttlMs: number,
    private readonly now: () => number = () => Date.now()
  ) {}

  get(key: string): T | undefined {
    const entry = this.store.get(key)

    if (!entry) {
      return undefined
    }

    if (entry.expiresAt <= this.now()) {
      this.store.delete(key)
      return undefined
    }

    return entry.value
  }

  set(key: string, value: T): void {
    // TTL <= 0 disables the cache — an entry is never actually stored.
    if (this.ttlMs <= 0) {
      return
    }

    this.store.set(key, { value, expiresAt: this.now() + this.ttlMs })
  }

  delete(key: string): void {
    this.store.delete(key)
  }

  clear(): void {
    this.store.clear()
  }

  get size(): number {
    return this.store.size
  }
}
