package abi

import (
	"fmt"
	"math"
	"strconv"

	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-state-types/big"
)

// SectorNumber is a numeric identifier for a sector. It is usually relative to a miner.
type SectorNumber uint64

func (s SectorNumber) String() string {
	return strconv.FormatUint(uint64(s), 10)
}

// The maximum assignable sector number.
// Raising this would require modifying our AMT implementation.
const MaxSectorNumber = math.MaxInt64

// SectorSize indicates one of a set of possible sizes in the network.
// Ideally, SectorSize would be an enum
// type SectorSize enum {
//   1KiB = 1024
//   1MiB = 1048576
//   1GiB = 1073741824
//   1TiB = 1099511627776
//   1PiB = 1125899906842624
//   1EiB = 1152921504606846976
//   max  = 18446744073709551615
// }
type SectorSize uint64

// Formats the size as a decimal string.
func (s SectorSize) String() string {
	return strconv.FormatUint(uint64(s), 10)
}

// Abbreviates the size as a human-scale number.
// This approximates (truncates) the size unless it is a power of 1024.
func (s SectorSize) ShortString() string {
	var biUnits = []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	unit := 0
	for s >= 1024 && unit < len(biUnits)-1 {
		s /= 1024
		unit++
	}
	return fmt.Sprintf("%d%s", s, biUnits[unit])
}

type SectorID struct {
	Miner  ActorID
	Number SectorNumber
}

// The unit of storage power (measured in bytes)
type StoragePower = big.Int

type SectorQuality = big.Int

func NewStoragePower(n int64) StoragePower {
	return big.NewInt(n)
}

// These enumerations must match the proofs library and never change.
type RegisteredSealProof int64

const (
	RegisteredSealProof_StackedDrg2KiBV2   = RegisteredSealProof(0)
	RegisteredSealProof_StackedDrg8MiBV2   = RegisteredSealProof(1)
	RegisteredSealProof_StackedDrg512MiBV2 = RegisteredSealProof(2)
	RegisteredSealProof_StackedDrg32GiBV2  = RegisteredSealProof(3)
	RegisteredSealProof_StackedDrg64GiBV2  = RegisteredSealProof(4)
)

type RegisteredPoStProof int64

const (
	RegisteredPoStProof_StackedDrgWinning2KiBV2   = RegisteredPoStProof(0)
	RegisteredPoStProof_StackedDrgWinning8MiBV2   = RegisteredPoStProof(1)
	RegisteredPoStProof_StackedDrgWinning512MiBV2 = RegisteredPoStProof(2)
	RegisteredPoStProof_StackedDrgWinning32GiBV2  = RegisteredPoStProof(3)
	RegisteredPoStProof_StackedDrgWinning64GiBV2  = RegisteredPoStProof(4)
	RegisteredPoStProof_StackedDrgWindow2KiBV2    = RegisteredPoStProof(5)
	RegisteredPoStProof_StackedDrgWindow8MiBV2    = RegisteredPoStProof(6)
	RegisteredPoStProof_StackedDrgWindow512MiBV2  = RegisteredPoStProof(7)
	RegisteredPoStProof_StackedDrgWindow32GiBV2   = RegisteredPoStProof(8)
	RegisteredPoStProof_StackedDrgWindow64GiBV2   = RegisteredPoStProof(9)
)

// Metadata about a seal proof type.
type SealProofInfo struct {
	SectorSize                 SectorSize
	WinningPoStProof           RegisteredPoStProof
	WindowPoStProof            RegisteredPoStProof
}

var SealProofInfos = map[RegisteredSealProof]*SealProofInfo{
	RegisteredSealProof_StackedDrg2KiBV2: {
		SectorSize:                 2 << 10,
		WinningPoStProof:           RegisteredPoStProof_StackedDrgWinning2KiBV2,
		WindowPoStProof:            RegisteredPoStProof_StackedDrgWindow2KiBV2,
	},
	RegisteredSealProof_StackedDrg8MiBV2: {
		SectorSize:                 8 << 20,
		WinningPoStProof:           RegisteredPoStProof_StackedDrgWinning8MiBV2,
		WindowPoStProof:            RegisteredPoStProof_StackedDrgWindow8MiBV2,
	},
	RegisteredSealProof_StackedDrg512MiBV2: {
		SectorSize:                 512 << 20,
		WinningPoStProof:           RegisteredPoStProof_StackedDrgWinning512MiBV2,
		WindowPoStProof:            RegisteredPoStProof_StackedDrgWindow512MiBV2,
	},
	RegisteredSealProof_StackedDrg32GiBV2: {
		SectorSize:                 32 << 30,
		WinningPoStProof:           RegisteredPoStProof_StackedDrgWinning32GiBV2,
		WindowPoStProof:            RegisteredPoStProof_StackedDrgWindow32GiBV2,
	},
	RegisteredSealProof_StackedDrg64GiBV2: {
		SectorSize:                 64 << 30,
		WinningPoStProof:           RegisteredPoStProof_StackedDrgWinning64GiBV2,
		WindowPoStProof:            RegisteredPoStProof_StackedDrgWindow64GiBV2,
	},
}

func (p RegisteredSealProof) SectorSize() (SectorSize, error) {
	info, ok := SealProofInfos[p]
	if !ok {
		return 0, xerrors.Errorf("unsupported proof type: %v", p)
	}
	return info.SectorSize, nil
}

// RegisteredWinningPoStProof produces the PoSt-specific RegisteredProof corresponding
// to the receiving RegisteredProof.
func (p RegisteredSealProof) RegisteredWinningPoStProof() (RegisteredPoStProof, error) {
	info, ok := SealProofInfos[p]
	if !ok {
		return 0, xerrors.Errorf("unsupported proof type: %v", p)
	}
	return info.WinningPoStProof, nil
}

// RegisteredWindowPoStProof produces the PoSt-specific RegisteredProof corresponding
// to the receiving RegisteredProof.
func (p RegisteredSealProof) RegisteredWindowPoStProof() (RegisteredPoStProof, error) {
	info, ok := SealProofInfos[p]
	if !ok {
		return 0, xerrors.Errorf("unsupported proof type: %v", p)
	}
	return info.WindowPoStProof, nil
}

var PoStSealProofTypes = map[RegisteredPoStProof]RegisteredSealProof{
	RegisteredPoStProof_StackedDrgWinning2KiBV2:   RegisteredSealProof_StackedDrg2KiBV2,
	RegisteredPoStProof_StackedDrgWindow2KiBV2:    RegisteredSealProof_StackedDrg2KiBV2,
	RegisteredPoStProof_StackedDrgWinning8MiBV2:   RegisteredSealProof_StackedDrg8MiBV2,
	RegisteredPoStProof_StackedDrgWindow8MiBV2:    RegisteredSealProof_StackedDrg8MiBV2,
	RegisteredPoStProof_StackedDrgWinning512MiBV2: RegisteredSealProof_StackedDrg512MiBV2,
	RegisteredPoStProof_StackedDrgWindow512MiBV2:  RegisteredSealProof_StackedDrg512MiBV2,
	RegisteredPoStProof_StackedDrgWinning32GiBV2:  RegisteredSealProof_StackedDrg32GiBV2,
	RegisteredPoStProof_StackedDrgWindow32GiBV2:   RegisteredSealProof_StackedDrg32GiBV2,
	RegisteredPoStProof_StackedDrgWinning64GiBV2:  RegisteredSealProof_StackedDrg64GiBV2,
	RegisteredPoStProof_StackedDrgWindow64GiBV2:   RegisteredSealProof_StackedDrg64GiBV2,
}

// Maps PoSt proof types back to seal proof types.
func (p RegisteredPoStProof) RegisteredSealProof() (RegisteredSealProof, error) {
	sp, ok := PoStSealProofTypes[p]
	if !ok {
		return 0, xerrors.Errorf("unsupported PoSt proof type: %v", p)
	}
	return sp, nil
}

func (p RegisteredPoStProof) SectorSize() (SectorSize, error) {
	sp, err := p.RegisteredSealProof()
	if err != nil {
		return 0, err
	}
	return sp.SectorSize()
}

type SealRandomness Randomness
type InteractiveSealRandomness Randomness
type PoStRandomness Randomness

