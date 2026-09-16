package mux

import "sync"

type semaphore struct {
	mu        sync.Mutex
	available int
	closed    bool
	waiters   []chan struct{}
}

func newSemaphore(n int) *semaphore {
	return &semaphore{available: n}
}

func (s *semaphore) acquire(n int, stop <-chan struct{}) error {
	if n < 0 {
		n = 0
	}
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return errClosed
		}
		if s.available >= n {
			s.available -= n
			s.mu.Unlock()
			return nil
		}
		ch := make(chan struct{})
		s.waiters = append(s.waiters, ch)
		s.mu.Unlock()
		select {
		case <-ch:
		case <-stop:
			return errClosed
		}
	}
}

func (s *semaphore) add(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	s.available += n
	s.wake()
	s.mu.Unlock()
}

func (s *semaphore) availablePermits() int {
	s.mu.Lock()
	n := s.available
	s.mu.Unlock()
	return n
}

func (s *semaphore) close() {
	s.mu.Lock()
	s.closed = true
	s.wake()
	s.mu.Unlock()
}

func (s *semaphore) wake() {
	waiters := s.waiters
	s.waiters = nil
	for _, ch := range waiters {
		close(ch)
	}
}
