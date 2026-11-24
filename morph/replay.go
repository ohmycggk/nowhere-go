package morph

import "sync"

const (
	replayCapacity = 16384
	replayWindow   = 1024
)

// replayRegistry is the in-process Morph TCP replay table for one Portal key
// set. It keeps at most 16384 identities in strict insertion order and a
// 1024-counter window for each. There is no TTL, persistence, or nonce cache.
//
// Both index and slots are pointer-free so the GC does not scan replay state
// even when all 16384 identities are populated.
type replayRegistry struct {
	mu    sync.Mutex
	index map[uint64]uint16
	slots []replaySlot
	start int
	count int
}

type replaySlot struct {
	identity uint64
	entry    replayEntry
}

type replayEntry struct {
	highest uint64
	bitmap  [replayWindow / 64]uint64
}

func newReplayRegistry() *replayRegistry {
	return &replayRegistry{index: make(map[uint64]uint16)}
}

func (r *replayRegistry) precheck(identity, counter uint64) bool {
	if !counterValid(counter) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx, ok := r.index[identity]
	if !ok {
		return true
	}
	return r.slots[idx].entry.accepts(counter)
}

func (r *replayRegistry) commit(identity, counter uint64) bool {
	if !counterValid(counter) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if idx, ok := r.index[identity]; ok {
		entry := &r.slots[idx].entry
		if !entry.accepts(counter) {
			return false
		}
		entry.mark(counter)
		return true
	}
	var slotIdx int
	if r.count == replayCapacity {
		slotIdx = r.start
		delete(r.index, r.slots[slotIdx].identity)
		r.slots[slotIdx] = replaySlot{
			identity: identity,
			entry:    replayEntry{highest: counter},
		}
		r.slots[slotIdx].entry.bitmap[0] = 1
		r.start = (r.start + 1) % replayCapacity
	} else {
		slotIdx = len(r.slots)
		r.slots = append(r.slots, replaySlot{
			identity: identity,
			entry:    replayEntry{highest: counter},
		})
		r.slots[slotIdx].entry.bitmap[0] = 1
		r.count++
	}
	r.index[identity] = uint16(slotIdx)
	return true
}

func counterValid(counter uint64) bool {
	return counter >= 1 && counter <= maxCounter
}

func (e *replayEntry) accepts(counter uint64) bool {
	if counter > e.highest {
		return true
	}
	distance := e.highest - counter
	return distance < replayWindow && e.bitmap[distance/64]&(1<<(distance%64)) == 0
}

func (e *replayEntry) mark(counter uint64) {
	if counter > e.highest {
		distance := counter - e.highest
		if distance >= replayWindow {
			for i := range e.bitmap {
				e.bitmap[i] = 0
			}
		} else {
			words := int(distance / 64)
			bits := uint(distance % 64)
			for index := len(e.bitmap) - 1; index >= 0; index-- {
				var value uint64
				if index >= words {
					value = e.bitmap[index-words] << bits
					if bits != 0 && index > words {
						value |= e.bitmap[index-words-1] >> (64 - bits)
					}
				}
				e.bitmap[index] = value
			}
		}
		e.highest = counter
	}
	distance := e.highest - counter
	e.bitmap[distance/64] |= 1 << (distance % 64)
}
