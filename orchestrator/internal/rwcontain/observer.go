// Package rwcontain implements rwevidence.ContainmentObserver over an EDR
// device-status source. It reads the host's current containment state after
// the attempt; it never triggers containment itself.
package rwcontain

import (
	"context"
	"errors"

	"github.com/audspect/bas/internal/rwdetect"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/vendors/crowdstrike"
)

// ErrDeviceNotFound means the vendor has no device for the host. That is an
// inconclusive answer, not a failure.
var ErrDeviceNotFound = errors.New("rwcontain: device not found")

// DeviceSource resolves a hostname to a vendor device and reads its
// containment status.
type DeviceSource interface {
	ResolveDevice(ctx context.Context, hostname string) (string, error)
	DeviceContainmentStatus(ctx context.Context, deviceID string) (string, error)
}

// Observer grades containment from the vendor's current device status.
//
// The status is a point-in-time read, so it shows the state when observed,
// not when the attempt happened. Only a "contained" status confirms
// containment. "normal" is verified not contained. Anything pending or unknown
// is indeterminate.
type Observer struct {
	Devices DeviceSource
	Context rwdetect.ContextSource
}

// ObserveContainment implements rwevidence.ContainmentObserver.
func (o Observer) ObserveContainment(ctx context.Context, key rwevidence.AttemptKey) (rwevidence.ContainmentResult, error) {
	ac, err := o.Context.AttemptContextFor(ctx, key)
	if err != nil {
		return "", err
	}
	if ac.HostName == "" {
		return rwevidence.ContainmentIndeterminate, nil
	}
	deviceID, err := o.Devices.ResolveDevice(ctx, ac.HostName)
	if errors.Is(err, ErrDeviceNotFound) {
		return rwevidence.ContainmentIndeterminate, nil
	}
	if err != nil {
		return "", err
	}
	status, err := o.Devices.DeviceContainmentStatus(ctx, deviceID)
	if errors.Is(err, ErrDeviceNotFound) {
		return rwevidence.ContainmentIndeterminate, nil
	}
	if err != nil {
		return "", err
	}
	switch status {
	case "contained":
		return rwevidence.ContainmentConfirmed, nil
	case "normal":
		return rwevidence.ContainmentFailed, nil
	default:
		return rwevidence.ContainmentIndeterminate, nil
	}
}

// CrowdStrikeSource adapts the CrowdStrike Falcon client to DeviceSource,
// mapping its not-found error onto ErrDeviceNotFound.
type CrowdStrikeSource struct {
	Client *crowdstrike.Client
}

func (s CrowdStrikeSource) ResolveDevice(ctx context.Context, hostname string) (string, error) {
	id, err := s.Client.ResolveDevice(ctx, hostname)
	if errors.Is(err, crowdstrike.ErrDeviceNotFound) {
		return "", ErrDeviceNotFound
	}
	return id, err
}

func (s CrowdStrikeSource) DeviceContainmentStatus(ctx context.Context, deviceID string) (string, error) {
	status, err := s.Client.DeviceContainmentStatus(ctx, deviceID)
	if errors.Is(err, crowdstrike.ErrDeviceNotFound) {
		return "", ErrDeviceNotFound
	}
	return status, err
}
