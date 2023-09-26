package profiler

import "time"

type ProfilerConfig struct {
	Enabled         bool
	UploaderEnabled bool

	Dir      string
	Interval time.Duration
	Duration time.Duration
}

func DefaultProfilerConfig() ProfilerConfig {
	return ProfilerConfig{
		Enabled:         false,
		UploaderEnabled: false,

		Dir:      "profiler",
		Interval: 15 * time.Minute,
		Duration: 10 * time.Second,
	}
}
