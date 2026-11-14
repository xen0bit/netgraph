package dnsserver

import (
	"container/list"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	cacheEntries = 10_000
	// cacheMaxTTL and cacheMinTTL clamp how long an answer is kept, whatever
	// it says; cacheNegTTL is for a "no such name" with no SOA to say.
	cacheMaxTTL = time.Hour
	cacheMinTTL = 5 * time.Second
	cacheNegTTL = time.Minute
)

// cache keeps upstream answers for their TTL. Keys are lower-cased names, so
// a client's 0x20 casing still hits.
type cache struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
	now     func() time.Time
}

type cacheEntry struct {
	key     string
	msg     []byte
	stored  time.Time
	expires time.Time
}

func newCache() *cache {
	return &cache{entries: map[string]*list.Element{}, lru: list.New(), now: time.Now}
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

func (c *cache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]*list.Element{}
	c.lru.Init()
}

// get returns a kept answer for id, its TTLs lowered by the time it was kept.
func (c *cache) get(key string, id uint16) ([]byte, bool) {
	c.mu.Lock()
	el, ok := c.entries[key]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	now := c.now()
	if !now.Before(e.expires) {
		c.lru.Remove(el)
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}
	c.lru.MoveToFront(el)
	msg, stored := e.msg, e.stored
	c.mu.Unlock()
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		return nil, false
	}
	age := uint32(now.Sub(stored) / time.Second)
	for _, rrs := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
		for i := range rrs {
			if rrs[i].Header.Type == dnsmessage.TypeOPT {
				continue
			}
			rrs[i].Header.TTL = max(rrs[i].Header.TTL, age) - age
		}
	}
	m.ID = id
	out, err := m.Pack()
	if err != nil {
		return nil, false
	}
	return out, true
}

// put keeps an answer, if it's one worth keeping: a success or a "no such
// name", for its smallest TTL.
func (c *cache) put(key string, msg []byte) {
	ttl, ok := cacheTTL(msg)
	if !ok {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		c.lru.Remove(el)
		delete(c.entries, key)
	}
	c.entries[key] = c.lru.PushFront(&cacheEntry{key: key, msg: msg, stored: now, expires: now.Add(ttl)})
	for c.lru.Len() > cacheEntries {
		old := c.lru.Back()
		c.lru.Remove(old)
		delete(c.entries, old.Value.(*cacheEntry).key)
	}
}

// cacheTTL is how long an answer may be kept (RFC 2308 for negative ones).
func cacheTTL(msg []byte) (time.Duration, bool) {
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil || m.Truncated {
		return 0, false
	}
	switch m.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	default:
		return 0, false
	}
	least := uint32(1 << 31)
	for _, r := range m.Answers {
		least = min(least, r.Header.TTL)
	}
	if len(m.Answers) == 0 {
		// Negative: the SOA's TTL or its minimum, whichever is less.
		least = uint32(cacheNegTTL / time.Second)
		for _, r := range m.Authorities {
			if soa, ok := r.Body.(*dnsmessage.SOAResource); ok {
				least = min(r.Header.TTL, soa.MinTTL)
			}
		}
	}
	ttl := time.Duration(least) * time.Second
	if ttl < cacheMinTTL {
		return 0, false
	}
	return min(ttl, cacheMaxTTL), true
}
