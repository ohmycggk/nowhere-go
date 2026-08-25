package mux

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func startPair(t *testing.T) (*Handle, *Incoming, *Handle, *Incoming) {
	t.Helper()
	left, right := net.Pipe()
	client, clientIn, err := Start(left, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	server, serverIn, err := Start(right, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, clientIn, server, serverIn
}

func TestStreamRoundTripAndHalfClose(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outgoing.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := outgoing.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	incoming, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(incoming)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("hello")) {
		t.Fatalf("got %q", payload)
	}
}

func TestIdleDeadlineResetsWhenStreamBecomesActive(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	idleDone := make(chan bool, 1)
	go func() {
		idleDone <- client.IdleFor(ctx, 80*time.Millisecond)
	}()
	time.Sleep(40 * time.Millisecond)
	outgoing, err := client.OpenStream(1)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-idleDone:
		t.Fatal("idle completed while a stream was active")
	case <-time.After(50 * time.Millisecond):
	}
	_ = outgoing.Close()
	_ = accepted.Close()
	select {
	case idle := <-idleDone:
		if !idle {
			t.Fatal("expected idle after streams closed")
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("idle did not complete")
	}
}

func TestManySmallWritesCrossCreditWindow(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	outgoing, err := client.OpenStream(8)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted, err := serverIn.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packet := bytes.Repeat([]byte{0x5a}, 1202)
	const count = 1024
	done := make(chan []byte, 1)
	go func() {
		got, err := io.ReadAll(io.LimitReader(accepted, int64(len(packet)*count)))
		if err != nil {
			t.Error(err)
		}
		done <- got
	}()
	for i := 0; i < count; i++ {
		if _, err := outgoing.Write(packet); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := outgoing.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if len(got) != len(packet)*count {
			t.Fatalf("len=%d want %d", len(got), len(packet)*count)
		}
		for _, b := range got {
			if b != 0x5a {
				t.Fatal("payload mismatch")
			}
		}
	case <-ctx.Done():
		t.Fatal("credit window stalled")
	}
}

func TestCarrierCloseFailsEveryFlow(t *testing.T) {
	client, _, server, serverIn := startPair(t)
	outgoing, err := client.OpenStream(9)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := serverIn.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	server.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := outgoing.Write([]byte("closed")); err != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("write kept succeeding after peer close")
}

func TestRapidStreamDropDoesNotCloseCarrier(t *testing.T) {
	client, _, server, serverIn := startPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for flowID := uint32(1); flowID <= 200; flowID++ {
		outgoing, err := client.OpenStream(flowID)
		if err != nil {
			t.Fatalf("open %d: %v", flowID, err)
		}
		accepted, err := serverIn.Accept(ctx)
		if err != nil {
			t.Fatalf("accept %d: %v", flowID, err)
		}
		_ = outgoing.Close()
		_ = accepted.Close()
	}
	if client.IsClosed() || server.IsClosed() {
		t.Fatal("carrier closed after rapid open/drop")
	}
}

func TestFairCreditTracksActiveStreamCount(t *testing.T) {
	client, _, _, serverIn := startPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var streams []*Stream
	for flowID := uint32(1); flowID <= 128; flowID++ {
		outgoing, err := client.OpenStream(flowID)
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, outgoing)
		if _, err := serverIn.Accept(ctx); err != nil {
			t.Fatal(err)
		}
	}
	client.shared.flowsMu.Lock()
	for _, flow := range client.shared.flows {
		if flow.fairLimit != minFairCredit {
			client.shared.flowsMu.Unlock()
			t.Fatalf("fair_limit=%d want %d", flow.fairLimit, minFairCredit)
		}
	}
	client.shared.flowsMu.Unlock()
	retained := streams[len(streams)-1]
	for _, stream := range streams[:len(streams)-1] {
		_ = stream.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		client.shared.flowsMu.Lock()
		n := len(client.shared.flows)
		var fair int
		for _, flow := range client.shared.flows {
			fair = flow.fairLimit
		}
		client.shared.flowsMu.Unlock()
		if n == 1 && fair == DefaultConfig().StreamWindowBytes {
			_ = retained.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("fair limit did not recover to the stream window")
}
