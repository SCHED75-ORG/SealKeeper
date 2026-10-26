package integrations

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Dispatcher fans audit events out to every enabled Sink.
//
// Design (SK-19):
//
//   - Push is non-blocking: the request pipeline never waits on a SIEM.
//   - Three lanes, drained in strict priority order. Events from the
//     public flow (request.*, token.*, mail.*, reveal.*, session.*) go to
//     the *bulk* lane. Security events an anonymous caller can still emit
//     at will (admin.login_failed: a rate-limited POST /admin/login costs
//     no credential and no bcrypt) go to the *anonymous* lane. Everything
//     else — events emitted after authentication (admin.created, smtp.*,
//     policy.*, integration.*, domain.*, …) and unknown types — goes to the
//     *security* lane. Each lane has its own bounded buffer, so a flood can
//     fill and drop only its own lane: request.rate_limited can neither
//     evict nor delay admin.login_failed, and a login_failed flood can
//     neither evict nor delay admin.created. The security lane is 4x larger
//     than bulk and the anonymous lane 2x; all are bounded so a
//     pathological storm cannot exhaust memory.
//   - One worker goroutine and one set of bounded queues *per sink*. A
//     slow or black-holed sink backs up and drops only its own queue; the
//     other sinks keep delivering. Each Send is bounded by the per-send
//     timeout (context) on top of the sink's own client timeout.
//   - The router caches the enabled-sink list (refreshed every
//     refreshEvery) instead of querying the DB once per event.
//   - Drops are never silent: counted per lane (Stats, Prometheus via
//     Describe/Collect), logged at most once per dropLogEvery, and each sink
//     receives a synthetic "integration.events_dropped" event carrying its
//     own drop counts as soon as it recovers, so the SIEM sees the gap.
//   - Filters that fail to parse match nothing (fail closed) and are logged.
type Dispatcher struct {
	repo       *Repo
	logger     *slog.Logger
	timeoutPer time.Duration
	bufSize    int
	pol        NetPolicy

	intake [numLanes]chan Event

	wg     sync.WaitGroup
	cancel context.CancelFunc

	refreshEvery time.Duration
	lastRefresh  time.Time
	workers      map[int64]*sinkWorker // router goroutine only

	dropLogEvery time.Duration
	lastDropLog  atomic.Int64 // unix nanos

	// Metrics (atomic so they're readable from any goroutine without lock).
	drops     [numLanes]atomic.Int64
	delivered atomic.Int64
	failed    atomic.Int64

	descDelivered *prometheus.Desc
	descFailed    *prometheus.Desc
	descDropped   *prometheus.Desc
}

// Lanes, highest priority first.
const (
	laneSecurity = iota
	laneAnonymous
	laneBulk
	numLanes
)

var laneNames = [numLanes]string{"security", "anonymous", "bulk"}

// anonymousEvents are the security-relevant event types a caller with no
// credential and no session can trigger in volume.
var anonymousEvents = map[string]bool{
	"admin.login_failed": true,
}

const (
	// EventDropsNotice is the synthetic event a sink receives after it
	// recovers from a period where its queue overflowed.
	EventDropsNotice = "integration.events_dropped"
)

// NewDispatcher returns a Dispatcher bound to a Repo. `bufSize` (default
// 256) sizes every bulk queue; security queues get 4x and anonymous queues
// 2x. `timeoutPer` (default 10s) bounds each individual sink delivery.
func NewDispatcher(repo *Repo, logger *slog.Logger, bufSize int, timeoutPer time.Duration) *Dispatcher {
	if bufSize <= 0 {
		bufSize = 256
	}
	if timeoutPer <= 0 {
		timeoutPer = 10 * time.Second
	}
	return &Dispatcher{
		repo:         repo,
		logger:       logger,
		timeoutPer:   timeoutPer,
		bufSize:      bufSize,
		intake:       newLanes(bufSize),
		refreshEvery: 2 * time.Second,
		dropLogEvery: 30 * time.Second,
		workers:      map[int64]*sinkWorker{},
		descDelivered: prometheus.NewDesc("sealkeeper_integrations_events_delivered_total",
			"Audit events delivered to outbound integrations.", nil, nil),
		descFailed: prometheus.NewDesc("sealkeeper_integrations_events_failed_total",
			"Audit event deliveries that failed (sink error or timeout).", nil, nil),
		descDropped: prometheus.NewDesc("sealkeeper_integrations_events_dropped_total",
			"Audit events dropped because a dispatcher queue was full.", []string{"lane"}, nil),
	}
}

// newLanes allocates one bounded queue per lane.
func newLanes(bufSize int) [numLanes]chan Event {
	var q [numLanes]chan Event
	q[laneSecurity] = make(chan Event, 4*bufSize)
	q[laneAnonymous] = make(chan Event, 2*bufSize)
	q[laneBulk] = make(chan Event, bufSize)
	return q
}

// WithNetPolicy sets the outbound address policy (SSRF guard) applied to
// every sink. Call before Start.
func (d *Dispatcher) WithNetPolicy(p NetPolicy) *Dispatcher {
	d.pol = p
	return d
}

// Start spawns the router goroutine; sink workers are spawned lazily as
// enabled integrations are discovered.
func (d *Dispatcher) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	d.cancel = cancel
	d.wg.Add(1)
	go d.run(ctx)
}

// Stop cancels the router and every worker and waits for them to exit.
func (d *Dispatcher) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
}

// IsBulkEvent reports whether an event type belongs to the droppable bulk
// lane, i.e. can be generated in volume by unauthenticated public traffic.
func IsBulkEvent(eventType string) bool {
	for _, p := range []string{"request.", "token.", "mail.", "reveal.", "session."} {
		if strings.HasPrefix(eventType, p) {
			return true
		}
	}
	return false
}

func laneIndex(eventType string) int {
	switch {
	case IsBulkEvent(eventType):
		return laneBulk
	case anonymousEvents[eventType]:
		return laneAnonymous
	default:
		return laneSecurity
	}
}

// LaneOf names the dispatcher lane an event type is queued in: "bulk",
// "anonymous" or "security" (the label of the dropped-events metric).
func LaneOf(eventType string) string { return laneNames[laneIndex(eventType)] }

// Push enqueues `ev` for delivery. Non-blocking — when the event's lane is
// full the event is dropped and counted.
func (d *Dispatcher) Push(ev Event) {
	lane := laneIndex(ev.EventType)
	select {
	case d.intake[lane] <- ev:
	default:
		d.noteDrop(lane, "", ev)
	}
}

// Stats snapshots the lifetime counters.
type Stats struct {
	Delivered      int64
	Failed         int64
	Drops          int64 // DropsSecurity + DropsAnonymous + DropsBulk
	DropsSecurity  int64
	DropsAnonymous int64
	DropsBulk      int64
}

// Stats returns a snapshot.
func (d *Dispatcher) Stats() Stats {
	sec, anon, bulk := d.drops[laneSecurity].Load(), d.drops[laneAnonymous].Load(), d.drops[laneBulk].Load()
	return Stats{
		Delivered:      d.delivered.Load(),
		Failed:         d.failed.Load(),
		Drops:          sec + anon + bulk,
		DropsSecurity:  sec,
		DropsAnonymous: anon,
		DropsBulk:      bulk,
	}
}

// Describe implements prometheus.Collector.
func (d *Dispatcher) Describe(ch chan<- *prometheus.Desc) {
	ch <- d.descDelivered
	ch <- d.descFailed
	ch <- d.descDropped
}

// Collect implements prometheus.Collector.
func (d *Dispatcher) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(d.descDelivered, prometheus.CounterValue, float64(d.delivered.Load()))
	ch <- prometheus.MustNewConstMetric(d.descFailed, prometheus.CounterValue, float64(d.failed.Load()))
	for lane := range d.drops {
		ch <- prometheus.MustNewConstMetric(d.descDropped, prometheus.CounterValue,
			float64(d.drops[lane].Load()), laneNames[lane])
	}
}

func (d *Dispatcher) noteDrop(lane int, sink string, ev Event) {
	d.drops[lane].Add(1)
	if d.logger == nil {
		return
	}
	// Rate-limited: one line per dropLogEvery, carrying the totals, so a
	// flood cannot also flood the logs.
	now := time.Now().UnixNano()
	last := d.lastDropLog.Load()
	if now-last < int64(d.dropLogEvery) || !d.lastDropLog.CompareAndSwap(last, now) {
		return
	}
	d.logger.Warn("integrations.Dispatcher: dropping events — queue full",
		"lane", laneNames[lane], "sink", sink, "event_type", ev.EventType,
		"dropped_security_total", d.drops[laneSecurity].Load(),
		"dropped_anonymous_total", d.drops[laneAnonymous].Load(),
		"dropped_bulk_total", d.drops[laneBulk].Load())
}

// recvByPriority blocks until an event is waiting and returns it with its
// lane, always taking from the highest-priority non-empty lane. ok is false
// once ctx is done or stop is closed (a nil stop never fires).
func recvByPriority(ctx context.Context, stop <-chan struct{}, q *[numLanes]chan Event) (Event, int, bool) {
	for lane := range q {
		select {
		case ev := <-q[lane]:
			return ev, lane, true
		default:
		}
	}
	select {
	case <-ctx.Done():
		return Event{}, 0, false
	case <-stop:
		return Event{}, 0, false
	case ev := <-q[laneSecurity]:
		return ev, laneSecurity, true
	case ev := <-q[laneAnonymous]:
		return ev, laneAnonymous, true
	case ev := <-q[laneBulk]:
		return ev, laneBulk, true
	}
}

// run is the router: drains the intake lanes in priority order and hands
// each event to the matching sink workers without waiting on them.
func (d *Dispatcher) run(ctx context.Context) {
	defer d.wg.Done()
	for ctx.Err() == nil {
		ev, lane, ok := recvByPriority(ctx, nil, &d.intake)
		if !ok {
			return
		}
		d.route(ctx, ev, lane)
	}
}

func (d *Dispatcher) route(ctx context.Context, ev Event, lane int) {
	d.refresh(ctx)
	for _, w := range d.workers {
		if !w.matches(ev.EventType) {
			continue
		}
		w.enqueue(d, ev, lane)
	}
}

// refresh reconciles the worker set with the enabled rows, at most once
// per refreshEvery. A row whose kind/config/filters changed gets a fresh
// worker; removed or disabled rows have their worker retired.
func (d *Dispatcher) refresh(ctx context.Context) {
	if !d.lastRefresh.IsZero() && time.Since(d.lastRefresh) < d.refreshEvery {
		return
	}
	rows, err := d.repo.ListEnabled(ctx)
	if err != nil {
		d.logf("ListEnabled failed", "err", err)
		return // keep the previous worker set
	}
	d.lastRefresh = time.Now()
	seen := make(map[int64]bool, len(rows))
	for i := range rows {
		row := rows[i]
		seen[row.ID] = true
		fp := fingerprint(row)
		if w, ok := d.workers[row.ID]; ok && w.fp == fp {
			continue
		} else if ok {
			w.retire()
			delete(d.workers, row.ID)
		}
		sink, err := BuildSink(row, d.pol)
		if err != nil {
			d.logf("BuildSink failed", "integration", row.Name, "err", err)
			d.failed.Add(1)
			continue
		}
		f, ferr := ParseFilters(row.FiltersJSON)
		if ferr != nil {
			d.logf("invalid filters_json — sink receives nothing until fixed",
				"integration", row.Name, "err", ferr)
		}
		w := &sinkWorker{
			fp:        fp,
			sink:      sink,
			filters:   f,
			filtersOK: ferr == nil,
			queues:    newLanes(d.bufSize),
			stop:      make(chan struct{}),
		}
		d.workers[row.ID] = w
		d.wg.Add(1)
		go w.run(ctx, d)
	}
	for id, w := range d.workers {
		if !seen[id] {
			w.retire()
			delete(d.workers, id)
		}
	}
}

func fingerprint(row Integration) string {
	return string(row.Kind) + "\x00" + string(row.ConfigJSON) + "\x00" + string(row.FiltersJSON)
}

// sinkWorker owns one sink: its queues, its goroutine, its drop debt.
type sinkWorker struct {
	fp        string
	sink      Sink
	filters   Filters
	filtersOK bool
	queues    [numLanes]chan Event
	stop      chan struct{}
	stopOnce  sync.Once

	// Drops per lane since the last notice delivered to this sink.
	pending [numLanes]atomic.Int64
}

func (w *sinkWorker) matches(eventType string) bool {
	return w.filtersOK && w.filters.Matches(eventType)
}

func (w *sinkWorker) retire() { w.stopOnce.Do(func() { close(w.stop) }) }

func (w *sinkWorker) enqueue(d *Dispatcher, ev Event, lane int) {
	select {
	case w.queues[lane] <- ev:
	default:
		w.pending[lane].Add(1)
		d.noteDrop(lane, w.sink.Name(), ev)
	}
}

func (w *sinkWorker) run(ctx context.Context, d *Dispatcher) {
	defer d.wg.Done()
	defer func() {
		if c, ok := w.sink.(interface{ closeIdle() }); ok {
			c.closeIdle()
		}
	}()
	for ctx.Err() == nil {
		ev, _, ok := recvByPriority(ctx, w.stop, &w.queues)
		if !ok {
			return
		}
		if d.send(ctx, w.sink, ev) {
			w.flushDropNotice(ctx, d, ev)
		}
	}
}

// flushDropNotice tells a recovered sink how many events it missed.
func (w *sinkWorker) flushDropNotice(ctx context.Context, d *Dispatcher, last Event) {
	var counts [numLanes]int64
	var total int64
	for lane := range counts {
		counts[lane] = w.pending[lane].Swap(0)
		total += counts[lane]
	}
	if total == 0 {
		return
	}
	details, _ := json.Marshal(map[string]any{
		"dropped_security":  counts[laneSecurity],
		"dropped_anonymous": counts[laneAnonymous],
		"dropped_bulk":      counts[laneBulk],
	})
	notice := NewEvent(0, EventDropsNotice, "system", w.sink.Name(), details,
		"", last.InstanceDomain, time.Now())
	if !d.send(ctx, w.sink, notice) {
		for lane, n := range counts {
			w.pending[lane].Add(n)
		}
	}
}

func (d *Dispatcher) send(ctx context.Context, s Sink, ev Event) bool {
	cctx, cancel := context.WithTimeout(ctx, d.timeoutPer)
	defer cancel()
	if err := s.Send(cctx, ev); err != nil {
		d.failed.Add(1)
		d.logf("sink.Send failed", "sink", s.Name(), "kind", string(s.Kind()), "err", err)
		return false
	}
	d.delivered.Add(1)
	return true
}

func (d *Dispatcher) logf(msg string, args ...any) {
	if d.logger == nil {
		return
	}
	d.logger.Warn("integrations.Dispatcher: "+msg, args...)
}

// TestSink delivers a synthetic event to `row`'s sink synchronously and
// returns the resulting error. Used by the /admin/integrations/{id}/test
// button. The error carries no remote response body (status code only).
func TestSink(ctx context.Context, row Integration, instanceDomain string, pol NetPolicy) error {
	sink, err := BuildSink(row, pol)
	if err != nil {
		return err
	}
	defer func() {
		if c, ok := sink.(interface{ closeIdle() }); ok {
			c.closeIdle()
		}
	}()
	ev := NewEvent(0, "integration.test", "admin", row.Name,
		json.RawMessage(`{"hello":"from sealkeeper test event"}`),
		"", instanceDomain, time.Now())
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return sink.Send(cctx, ev)
}
