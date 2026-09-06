//go:build !windows && !linux && !darwin

package pressure

import "errors"

var errUnsupportedPlatform = errors.New("pressure: host sampling not implemented on this platform")

// SampleHost and SampleSelf on an unrecognized GOOS always fail, so the
// pressure loop degrades to "never throttle" (every tick is skipped, per
// agent/pressure_loop.go's error handling) rather than the agent failing to
// build at all -- mirrors agent/detect_other.go's fallback role exactly.
func SampleHost() (cpuPercent, memPercent float64, err error) {
	return 0, 0, errUnsupportedPlatform
}

func SampleSelf() (cpuPercent, memPercent float64, err error) {
	return 0, 0, errUnsupportedPlatform
}
