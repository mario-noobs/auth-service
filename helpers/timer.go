package helpers

import (
	"time"
)

// Timer struct to hold the start time and provide methods to start and stop timing
type Timer struct {
	start time.Time
}

// Start method to initialize the timer
func (t *Timer) Start() {
	t.start = time.Now()
}

// End method to calculate and return the elapsed time in milliseconds
func (t *Timer) End() int64 {
	elapsed := time.Since(t.start)
	return elapsed.Milliseconds()
}
