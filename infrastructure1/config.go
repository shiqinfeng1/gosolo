package infrastructure1

import (
	"time"
)

// Config encapsulation of configuration structs for all components related to xxx.
type Config struct {
	UnicastRateLimitersConfig `mapstructure:",squash"`
	AlspConfig                `mapstructure:",squash"`
	NetworkConnectionPruning  bool `mapstructure:"networking-connection-pruning"`
}

// UnicastRateLimitersConfig unicast rate limiter configuration for the message and bandwidth rate limiters.
type UnicastRateLimitersConfig struct {
	DryRun          bool          `mapstructure:"unicast-dry-run"`
	LockoutDuration time.Duration `validate:"gte=0" mapstructure:"unicast-lockout-duration"`
}

// AlspConfig is the config for the Application Layer Spam Prevention (ALSP) protocol.
type AlspConfig struct {
	SpamRecordCacheSize uint32 `mapstructure:"alsp-spam-record-cache-size"`
}
