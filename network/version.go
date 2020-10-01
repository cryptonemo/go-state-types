package network

import "math"

// Enumeration of network upgrades where actor behaviour can change (without necessarily
// vendoring and versioning the whole actor codebase).
type Version uint

const (
	Version0 = Version(iota) // 00000000: genesis   (specs-actors v0.9.3)
	Version1                 // 00041280: breeze    (specs-actors v0.9.7)
	Version2                 // 00051000: smoke     (specs-actors v0.9.)
	Version3                 // 00094000: ignition  (specs-actors v0.9)
	Version4                 // 00128888: actors v2 (specs-actors v2.0.x (future))
	Version5                 // 00148888: liftoff   (specs-actors v2.0.x (future))

	// VersionCount is the number of versions defined.
	VersionCount

	// VersionMax is the maximum version number
	VersionMax = Version(math.MaxUint32)
)
