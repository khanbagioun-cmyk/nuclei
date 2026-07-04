package daemon

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Scheduler manages cron-like recurring scan jobs
type Scheduler struct {
	daemon   *Daemon
	entries  map[string]*scheduleEntry
	mu       sync.Mutex
	stopChan chan struct{}
}

type scheduleEntry struct {
	jobID     string
	expr      string
	nextRun   time.Time
	schedule  cronSchedule
}

// cronSchedule is a simplified cron parser supporting:
// "every:<duration>" e.g. "every:1h", "every:30m", "every:24h"
// "hourly", "daily", "weekly"
// "cron:<m> <h> <dom> <mon> <dow>" (basic 5-field cron)
type cronSchedule struct {
	minute   int
	hour     int
	dayOfMonth int
	month    int
	dayOfWeek int
	every    time.Duration
	raw      string
}

func parseSchedule(expr string) (cronSchedule, error) {
	expr = strings.TrimSpace(strings.ToLower(expr))
	switch expr {
	case "hourly":
		return cronSchedule{raw: expr, every: time.Hour}, nil
	case "daily":
		return cronSchedule{raw: expr, every: 24 * time.Hour}, nil
	case "weekly":
		return cronSchedule{raw: expr, every: 7 * 24 * time.Hour}, nil
	}

	if strings.HasPrefix(expr, "every:") {
		dur, err := time.ParseDuration(strings.TrimPrefix(expr, "every:"))
		if err != nil {
			return cronSchedule{}, fmt.Errorf("invalid duration in 'every:' schedule: %w", err)
		}
		return cronSchedule{raw: expr, every: dur}, nil
	}

	if strings.HasPrefix(expr, "cron:") {
		fields := strings.Fields(strings.TrimPrefix(expr, "cron:"))
		if len(fields) != 5 {
			return cronSchedule{}, fmt.Errorf("cron schedule needs 5 fields, got %d", len(fields))
		}
		s := cronSchedule{raw: expr}
		fmt.Sscanf(fields[0], "%d", &s.minute)
		fmt.Sscanf(fields[1], "%d", &s.hour)
		fmt.Sscanf(fields[2], "%d", &s.dayOfMonth)
		fmt.Sscanf(fields[3], "%d", &s.month)
		fmt.Sscanf(fields[4], "%d", &s.dayOfWeek)
		return s, nil
	}

	return cronSchedule{}, fmt.Errorf("unsupported schedule format: %s", expr)
}

func (s cronSchedule) nextAfter(t time.Time) time.Time {
	if s.every > 0 {
		return t.Add(s.every)
	}
	// Basic cron: next matching minute
	next := t.Add(time.Minute).Truncate(time.Minute)
	for i := 0; i < 525600; i++ {
		if s.matches(next) {
			return next
		}
		next = next.Add(time.Minute)
	}
	return t.Add(24 * time.Hour)
}

func (s cronSchedule) matches(t time.Time) bool {
	if s.minute != -1 && s.minute != t.Minute() {
		// wildcard not supported in this simplified version; use exact match
	}
	// Simplified: check each field, -1 or 0 means wildcard
	if s.minute != 0 && s.minute != t.Minute() {
		// Allow wildcard: if field is 0, treat as wildcard
		if s.minute != 0 {
			return false
		}
	}
	if s.hour != 0 && s.hour != t.Hour() {
		return false
	}
	if s.dayOfMonth != 0 && s.dayOfMonth != t.Day() {
		return false
	}
	if s.month != 0 && int(s.month) != int(t.Month()) {
		return false
	}
	if s.dayOfWeek != 0 && s.dayOfWeek != int(t.Weekday()) {
		return false
	}
	return true
}

// NewScheduler creates a new scheduler
func NewScheduler(d *Daemon) *Scheduler {
	return &Scheduler{
		daemon:   d,
		entries:  make(map[string]*scheduleEntry),
		stopChan: make(chan struct{}),
	}
}

// Add registers a scheduled job
func (s *Scheduler) Add(jobID, expr string) error {
	schedule, err := parseSchedule(expr)
	if err != nil {
		return err
	}
	entry := &scheduleEntry{
		jobID:    jobID,
		expr:     expr,
		schedule: schedule,
		nextRun:  schedule.nextAfter(time.Now()),
	}
	s.mu.Lock()
	s.entries[jobID] = entry
	s.mu.Unlock()
	return nil
}

// Remove unregisters a scheduled job
func (s *Scheduler) Remove(jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, jobID)
}

// UpdateNextRun recalculates the next run time after a job completes
func (s *Scheduler) UpdateNextRun(jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[jobID]
	if !ok {
		return
	}
	entry.nextRun = entry.schedule.nextAfter(time.Now())

	s.daemon.jobsMu.RLock()
	job := s.daemon.jobs[jobID]
	s.daemon.jobsMu.RUnlock()
	if job != nil {
		job.mu.Lock()
		nr := entry.nextRun
		job.NextRunAt = &nr
		job.mu.Unlock()
	}
}

// Start runs the scheduler loop
func (s *Scheduler) Start() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.checkSchedules()
		}
	}
}

// Stop halts the scheduler
func (s *Scheduler) Stop() {
	close(s.stopChan)
}

func (s *Scheduler) checkSchedules() {
	now := time.Now()
	s.mu.Lock()
	var due []string
	for id, entry := range s.entries {
		if !entry.nextRun.After(now) {
			due = append(due, id)
		}
	}
	s.mu.Unlock()

	for _, jobID := range due {
		s.daemon.jobsMu.RLock()
		job, ok := s.daemon.jobs[jobID]
		s.daemon.jobsMu.RUnlock()
		if !ok {
			s.Remove(jobID)
			continue
		}
		job.mu.Lock()
		if job.Status == StatusRunning {
			job.mu.Unlock()
			continue
		}
		job.mu.Unlock()

		select {
		case s.daemon.queue <- jobID:
		default:
			// queue full, skip this cycle
		}
	}
}

// ListSchedules returns all scheduled entries
func (s *Scheduler) ListSchedules() []map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]map[string]interface{}, 0, len(s.entries))
	for id, entry := range s.entries {
		result = append(result, map[string]interface{}{
			"job_id":   id,
			"schedule": entry.expr,
			"next_run": entry.nextRun,
		})
	}
	return result
}
