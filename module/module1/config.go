package module1

import "time"

type Config struct {
	RetryInterval time.Duration // the initial interval before we retry a request, uses exponential backoff
	Tolerance     uint          // determines how big of a difference in block heights we tolerated before actively syncing with range requests
	MaxAttempts   uint          // the maximum number of attempts we make for each requested block/height before discarding
	MaxSize       uint          // the maximum number of blocks we request in the same block request message
	MaxRequests   uint          // the maximum number of requests we send during each scanning period
}

func DefaultConfig() Config {
	return Config{
		RetryInterval: 4 * time.Second,
		Tolerance:     10,
		MaxAttempts:   5,
		MaxSize:       64,
		MaxRequests:   3,
	}
}
