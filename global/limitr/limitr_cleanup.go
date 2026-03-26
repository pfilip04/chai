package limitr

import "time"

func (rl *RateLimiter) LimiterCleanup(lifetime time.Duration) {

	for {

		time.Sleep(time.Minute)

		rl.mu.Lock()

		for ip, c := range rl.clients {

			if time.Since(c.lastSeenAt) > lifetime {

				delete(rl.clients, ip)
			}
		}

		rl.mu.Unlock()
	}
}
