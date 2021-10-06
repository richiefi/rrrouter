package metrics

import (
	"context"
	"fmt"
	"github.com/richiefi/rrrouter/util"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"time"
)

/*
	In the context-initiating function:
	m := metrics.NewMetrics(or.URL.RequestURI(), senders, timeout)
	ctx := context.WithValue(or.Context(), "metrics", m)
	defer m.ReportAndClose(time.Now())

	Deeper in the stack, where ctx is passed, at the start of the function:
	defer m.FromContext(ctx).MarkTime(time.Now())

	Mark specific points inside a function:
	m.FromContext(ctx).MarkTimeWith("setAccessTime-Storable")
*/

type Metrics interface {
	MarkTime(time.Time) Metrics
	MarkTimeWith(string) Metrics
	Mark(interface{}, interface{}) Metrics
	ReportAndClose(time.Time)
	WithSampleRate(float64) Metrics
}

func NewMetrics(ctx interface{}, senders *[]Sender, timeout *time.Duration) Metrics {
	m := metrics{}
	m.ctx = ctx
	m.times = make([]timeFunc, 0)
	now := time.Now()
	m.times = append(m.times, timeFunc{now, now, callerName(2), "", false})
	m.timesL = sync.Mutex{}
	m.values = make([]cv, 0)
	m.valuesL = sync.Mutex{}
	m.rc = make(chan bool, 1)
	m.timeout = timeout
	if senders == nil {
		if util.EnvBool("METRICS_DEBUG") {
			ss := make([]Sender, 1)
			ss[0] = &printSender{}
			senders = &ss
		}
	}
	m.senders = senders
	go m.waitForReport()
	return &m
}

type metrics struct {
	ctx     interface{}
	times   []timeFunc
	timesL  sync.Mutex
	values  []cv
	valuesL sync.Mutex
	rc      chan bool
	closed  bool
	senders *[]Sender
	timeout *time.Duration
	sr      *float64
}

type Sender interface {
	SendTimings(*interface{}, *[]timeFunc)
	SendValues(*interface{}, *[]cv)
}

type timeFunc struct {
	b  time.Time
	d  time.Time
	f  string
	w  string
	to bool
}

type cv struct {
	ctx   interface{}
	value interface{}
	ts    time.Time
}

func (m *metrics) MarkTime(b time.Time) Metrics {
	m.markTime(4, b, time.Now(), "", false)
	return m
}

func (m *metrics) MarkTimeWith(s string) Metrics {
	m.markTime(4, time.Now(), time.Now(), s, false)
	return m
}

func (m *metrics) markTime(skip int, b, d time.Time, with string, to bool) {
	m.timesL.Lock()
	defer m.timesL.Unlock()
	var f string
	if to {
		f = "timeout"
	} else {
		f = callerName(skip)
	}
	tf := timeFunc{
		b:  b,
		d:  d,
		f:  f,
		w:  with,
		to: to,
	}
	m.times = append(m.times, tf)
}

func (m *metrics) markTimeout() {
	now := time.Now()
	m.markTime(4, now, now, "", true)
}

func (m *metrics) Mark(ctx interface{}, val interface{}) Metrics {
	m.mark(ctx, val, time.Now())
	return m
}

func (m *metrics) mark(ctx interface{}, val interface{}, ts time.Time) {
	m.valuesL.Lock()
	defer m.valuesL.Unlock()
	m.values = append(m.values, cv{ctx, val, ts})
	m.closed = true
	m.rc <- true
}

func FromContext(ctx context.Context) Metrics {
	if ctx == nil {
		return &dummyMetrics{}
	}
	if v := ctx.Value("metrics"); v != nil {
		if cv, ok := v.(*metrics); ok {
			return cv
		}
	}

	return &dummyMetrics{}
}

func (m *metrics) ReportAndClose(b time.Time) {
	m.markTime(4, b, time.Now(), "", false)
	m.closed = true
	m.rc <- true
}

func (m *metrics) WithSampleRate(f float64) Metrics {
	m.sr = &f
	return m
}

var r *rand.Rand

func (m *metrics) doSendSample() bool {
	if m.sr == nil {
		return true
	}
	sr := *m.sr
	if sr == 1 {
		return true
	} else if sr == 0 {
		return false
	}
	if r == nil {
		r = rand.New(rand.NewSource(time.Now().Unix()))
	}
	return r.Float64() < sr
}

func (m *metrics) waitForReport() {
	var to time.Duration
	if m.timeout != nil {
		to = *m.timeout
	} else {
		to = time.Second * 60
	}
	for {
		select {
		case <-m.rc:
			break
		case <-time.After(to):
			m.markTimeout()
		}
		doSend := m.doSendSample()
		if m.senders != nil {
			for _, s := range *m.senders {
				m.timesL.Lock()
				if doSend {
					s.SendTimings(&m.ctx, &m.times)
				}
				m.times = make([]timeFunc, 0)
				m.timesL.Unlock()
				m.valuesL.Lock()
				if doSend {
					s.SendValues(&m.ctx, &m.values)
				}
				m.values = make([]cv, 0)
				m.valuesL.Unlock()
			}
		}
		if m.closed {
			return
		}
	}
}

func callerName(skip int) string {
	pc := make([]uintptr, 1)
	runtime.Callers(skip, pc)
	if f := runtime.FuncForPC(pc[0]); f != nil {
		return f.Name()
	}
	return "unknown func"
}

type printSender struct {
}

type byB []timeFunc

func (a byB) Len() int           { return len(a) }
func (a byB) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byB) Less(i, j int) bool { return a[i].b.Sub(a[j].b).Nanoseconds() < 0 }

func (ps *printSender) SendTimings(ctx *interface{}, ts *[]timeFunc) {
	if ts == nil || len(*ts) < 2 {
		return
	}
	var threshold time.Duration
	mt, err := util.EnvInt("METRICS_THRESHOLD_MS")
	if err == nil {
		threshold = time.Millisecond * time.Duration(mt)
	} else {
		threshold = time.Millisecond * 5000
	}
	first := (*ts)[0]
	last := (*ts)[len(*ts)-1]
	if last.d.Sub(last.b) < threshold {
		return
	}
	s := fmt.Sprintf("%v: metrics context: %v\n", first.b, *ctx)

	sort.Sort(byB(*ts))
	for _, tf := range (*ts)[1:] {
		if len(tf.w) > 0 {
			s += fmt.Sprintf("@%vms: %v--%v, duration: %vms, ts:%v\n", float64(tf.b.Sub(first.b).Microseconds())/1000, tf.f, tf.w, float64(tf.d.Sub(tf.b).Microseconds())/1000, tf.b)
		} else {
			s += fmt.Sprintf("@%vms: %v, duration: %vms\n", float64(tf.b.Sub(first.b).Microseconds())/1000, tf.f, float64(tf.d.Sub(tf.b).Microseconds())/1000)
		}
	}
	fmt.Println(s)
}

func (ps *printSender) SendValues(ctx *interface{}, vals *[]cv) {
	if *vals == nil {
		return
	}
	for _, cv := range *vals {
		fmt.Printf("%v metrics: %v: %v\n", cv.ts, cv.ctx, cv.value)
	}
}

//

type dummyMetrics struct {
}

func (m *dummyMetrics) MarkTime(b time.Time) Metrics {
	return m
}

func (m *dummyMetrics) MarkTimeWith(s string) Metrics {
	return m
}

func (m *dummyMetrics) Mark(ctx interface{}, val interface{}) Metrics {
	return m
}

func (m *dummyMetrics) ReportAndClose(time.Time) {
}

func (m *dummyMetrics) WithSampleRate(float64) Metrics {
	return m
}
