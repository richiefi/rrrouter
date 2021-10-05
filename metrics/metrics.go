package metrics

import (
	"context"
	"fmt"
	"github.com/richiefi/rrrouter/util"
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
	ReportAndClose(time.Time)
}

func NewMetrics(ctx interface{}, senders *[]Sender, timeout *time.Duration) Metrics {
	m := metrics{}
	m.ctx = ctx
	m.times = make([]timeFunc, 0)
	now := time.Now()
	m.times = append(m.times, timeFunc{now, now, callerName(2), "", false})
	m.timesL = sync.Mutex{}
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
	rc      chan bool
	senders *[]Sender
	timeout *time.Duration
}

type Sender interface {
	Send(ctx *interface{}, ts *[]timeFunc)
}

type timeFunc struct {
	b  time.Time
	d  time.Time
	f  string
	w  string
	to bool
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
	m.rc <- true
}

func (m *metrics) waitForReport() {
	var to time.Duration
	if m.timeout != nil {
		to = *m.timeout
	} else {
		to = time.Second * 60
	}
	select {
	case <-m.rc:
		break
	case <-time.After(to):
		m.markTimeout()
	}
	if m.senders != nil {
		for _, s := range *m.senders {
			s.Send(&m.ctx, &m.times)
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

func (ps *printSender) Send(ctx *interface{}, ts *[]timeFunc) {
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

//

type dummyMetrics struct {
}

func (m *dummyMetrics) MarkTime(b time.Time) Metrics {
	return m
}

func (m *dummyMetrics) MarkTimeWith(s string) Metrics {
	return m
}

func (m *dummyMetrics) ReportAndClose(time.Time) {
}
