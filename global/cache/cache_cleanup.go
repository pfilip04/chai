package cache

import "time"

func (ch *Cache) cacheCleanup() {

	for {

		time.Sleep(time.Minute)

		ch.mu.Lock()

		for key, identity := range ch.lookupMap {

			now := time.Now().UTC()

			if now.After(identity.ExpiresAt) {

				delete(ch.lookupMap, key)
			}
		}

		ch.mu.Unlock()
	}
}
