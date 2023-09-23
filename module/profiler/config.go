package profiler

import "time"

type ProfilerConfig struct {
	Enabled         bool
	UploaderEnabled bool

	Dir      string
	Interval time.Duration
	Duration time.Duration
}
