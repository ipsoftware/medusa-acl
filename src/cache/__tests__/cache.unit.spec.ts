import { TtlCache } from ".."

describe("TtlCache", () => {
  let now = 0
  const clock = () => now

  beforeEach(() => {
    now = 1_000
  })

  it("returns a stored value", () => {
    const cache = new TtlCache<string>(100, clock)
    cache.set("a", "x")

    expect(cache.get("a")).toBe("x")
    expect(cache.get("missing")).toBeUndefined()
  })

  it("forgets once the TTL elapses", () => {
    const cache = new TtlCache<string>(100, clock)
    cache.set("a", "x")

    now += 99
    expect(cache.get("a")).toBe("x")

    now += 1
    expect(cache.get("a")).toBeUndefined()
    // An expired entry is actually removed, not just no longer returned.
    expect(cache.size).toBe(0)
  })

  it("a TTL of zero disables the cache", () => {
    const cache = new TtlCache<string>(0, clock)
    cache.set("a", "x")

    expect(cache.get("a")).toBeUndefined()
    expect(cache.size).toBe(0)
  })

  it("supports invalidating a single entry and clearing everything", () => {
    const cache = new TtlCache<string>(100, clock)
    cache.set("a", "x")
    cache.set("b", "y")

    cache.delete("a")
    expect(cache.get("a")).toBeUndefined()
    expect(cache.get("b")).toBe("y")

    cache.clear()
    expect(cache.size).toBe(0)
  })

  it("overwriting refreshes the TTL", () => {
    const cache = new TtlCache<string>(100, clock)
    cache.set("a", "x")

    now += 90
    cache.set("a", "z")
    now += 90

    expect(cache.get("a")).toBe("z")
  })
})
