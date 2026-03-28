package limitr

import "time"

func (rl *RateLimiter) limiterCleanup(ipLifetime time.Duration, identifierLifetime time.Duration) {

	for {

		time.Sleep(time.Minute)

		rl.mu.Lock()

		// Cleaning IP clients

		for ip, c := range rl.ipClients {

			if time.Since(c.lastSeenAt) > ipLifetime {

				delete(rl.ipClients, ip)
			}
		}

		// Cleaning UserID clients

		for userId, c := range rl.userClients {

			if time.Since(c.lastSeenAt) > identifierLifetime {

				delete(rl.userClients, userId)
			}
		}

		rl.mu.Unlock()
	}
}
