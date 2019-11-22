package cachemap

import (
	"context"
	"sync"
	"time"
)

type CacheMap struct {
	*sync.Map
	ticker *time.Ticker
	ttl    time.Duration
	ctx    context.Context
}

func NewCacheMap(ctx context.Context, ttl time.Duration, check time.Duration) (c *CacheMap) {
	c = &CacheMap{
		Map:    &sync.Map{},
		ticker: time.NewTicker(check),
		ttl:    ttl,
		ctx:    ctx,
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.ticker.C:
				c.Range(func(key, value interface{}) bool {
					expireTime := value.(time.Time)
					if time.Since(expireTime) > c.ttl {
						c.Delete(key)
					}
					return true
				})
			}
		}
	}()
	return c
}
