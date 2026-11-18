package protocol

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestSessionGeneration(t *testing.T) {
	user := &MemoryUser{Email: "same@example.test"}
	old, next := user.NewGeneration(), user.NewGeneration()
	entered, resume, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release, ok := old.Sessions.Track(func() {
		close(entered)
		<-resume
	})
	if !ok {
		t.Fatal("new account rejected")
	}
	cancelled := false
	releaseFinished, _ := old.Sessions.Track(func() { cancelled = true })
	releaseFinished()
	cleanup := old.Sessions.Revoke()
	go func() { defer close(finished); cleanup() }()
	<-entered
	// Closing can block; both admission and release must still make progress.
	release()
	if _, ok := old.Sessions.Track(func() {}); ok {
		t.Fatal("revoked generation admitted a new stream")
	}
	nextRelease, ok := next.Sessions.Track(func() { t.Error("old cleanup touched replacement account") })
	if !ok {
		t.Fatal("new generation rejected")
	}
	close(resume)
	<-finished
	nextRelease()
	if cancelled {
		t.Fatal("completed resource retained by registry")
	}
}

func TestConcurrentSessionAdmission(t *testing.T) {
	var sessions UserSessions
	var accepted, stopped atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			<-start
			if _, ok := sessions.Track(func() { stopped.Add(1) }); ok {
				accepted.Add(1)
			}
		})
	}
	close(start)
	sessions.Revoke()()
	wg.Wait()
	if stopped.Load() != accepted.Load() {
		t.Fatalf("stopped %d of %d admitted sessions", stopped.Load(), accepted.Load())
	}
}
