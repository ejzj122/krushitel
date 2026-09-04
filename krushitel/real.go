package main

// real.go — оболочка экрана прогона для РЕАЛЬНЫХ движков krushitel
// (exploit/scanner/cloud/xmlde/ironscan через go.mod replace).
//
// Режим exploit показывает ЖИВЫЕ СТРОКИ СЕССИЙ (Stats.SetRow): у каждого
// серийника одна строка, обновляющаяся на месте по стадиям
// (пречек → туннель → exploit… → PWNED!/ADDED/FAIL/OFFLINE).
// Остальные режимы — лента событий, размер которой подстраивается
// под высоту терминала. Help-строку здесь НЕ рисуем — её прижимает
// к низу withBottom (иначе дубль).

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"krushitel/exploit"
	"krushitel/scanner"
)

const (
	runExploit = iota
	runCheck
	runGen
	runPrefix
	runTitles
)

// runState — состояние живого прогона (реальные движки).
type runState struct {
	mode     int
	panel    string
	cancel   context.CancelFunc
	start    time.Time
	endTime  time.Time // момент финиша — таймер замирает на нём
	h        int       // высота терминала (обновляется из тика)
	events   []string
	eventsCh chan string

	// exploit (krushitel/exploit)
	exp *exploit.Stats
	// check (krushitel/scanner)
	chk *scanner.ScanStats
	// titles (krushitel/exploit, подменю «титры по списку»)
	ttl *exploit.TitlesStats
	// generate (krushitel/cloud)
	genWritten int64
	genTotal   int64
	genDone    int64 // atomic: 1 = GenerateSerials вернулся
	genFile    string
	genErr     string
	// prefix (krushitel/ironscan)
	preScanned int64
	preFound   int64
	preTotal   int
	preDone    int64 // atomic

	// файл логов прогона (append в папку результатов)
	logFile *os.File
	logMu   sync.Mutex
}

func newRunState(mode int, panel string) *runState {
	return &runState{
		mode:     mode,
		panel:    panel,
		start:    time.Now(),
		eventsCh: make(chan string, 256),
	}
}

// openLog — включает запись ленты в файл (append). Путь пустой/ошибка —
// лог-файла нет, экранная лента работает как раньше.
func (r *runState) openLog(path string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	r.logFile = f
}

// writeLog — строка → файл с таймштампом (потокобезопасно; dbg-строки
// из сотен туннелей пишутся напрямую, минуя каналы — иначе лог решето).
func (r *runState) writeLog(line string) {
	if r.logFile == nil {
		return
	}
	ts := time.Now().Format("15:04:05")
	plain := stripANSI(line)
	r.logMu.Lock()
	r.logFile.WriteString(fmt.Sprintf("[%s] %s\n", ts, plain))
	r.logMu.Unlock()
}

// closeLog — флуш и закрытие (выход из прогона).
func (r *runState) closeLog() {
	if r.logFile != nil {
		r.logFile.Close()
		r.logFile = nil
	}
}

// stripANSI — срезает ANSI-коды раскраски: в файле логов цвет не нужен.
func stripANSI(s string) string {
	if !strings.Contains(s, "\x1b[") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z')) {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

// logMax — сколько строк ленты влезает: высота минус баннер/панель/
// статус/подсказка (≈15), зажато в [3..400].
func (r *runState) logMax() int {
	n := r.h - 15
	if n < 3 {
		n = 3
	}
	if n > 400 {
		n = 400
	}
	return n
}

// drain — перекладка событий движков в ленту (размер — по высоте).
// Каждая строка дублируется в лог-файл, если открыт.
func (r *runState) drain() {
	max := r.logMax()
	for {
		select {
		case ev := <-r.eventsCh:
			r.events = append(r.events, ev)
			if len(r.events) > max {
				r.events = r.events[len(r.events)-max:]
			}
			r.writeLog(ev)
		default:
			return
		}
	}
}

func (r *runState) finished() bool {
	switch r.mode {
	case runExploit:
		// прогон завершён, только когда и движок дошёл до конца, И
		// хвост extras (титры/снапы) догорел: ранний esc убивает
		// недоделанные снапы, «готово» не должно врать
		return r.exp != nil && r.exp.Done &&
			atomic.LoadInt64(&r.exp.ExtrasInFlight) == 0
	case runCheck:
		return r.chk != nil && r.chk.Done
	case runGen:
		return atomic.LoadInt64(&r.genDone) == 1
	case runPrefix:
		return atomic.LoadInt64(&r.preDone) == 1
	case runTitles:
		return r.ttl != nil && r.ttl.Done
	}
	return false
}

// elapsed — таймер от начала скана; после финиша замирает на конечном
// времени (счёт не убегает, пока любуешься результатом).
func (r *runState) elapsed() string {
	if r.finished() {
		if r.endTime.IsZero() {
			r.endTime = time.Now()
		}
		return fmtDuration(r.endTime.Sub(r.start).Seconds())
	}
	return fmtDuration(time.Since(r.start).Seconds())
}

func (r *runState) statusMsg() string {
	switch r.mode {
	case runExploit:
		return r.exp.ErrorMsg
	case runCheck:
		return r.chk.ErrorMsg
	case runGen:
		return r.genErr
	case runTitles:
		return r.ttl.ErrorMsg
	}
	return ""
}

// view — экран прогона с реальными счётчиками движка.
func (r *runState) view() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
	sb.WriteString(panelS(r.panel) + "\n\n")

	if msg := r.statusMsg(); msg != "" {
		sb.WriteString(centerLine(red(msg)) + "\n")
		return sb.String()
	}

	switch r.mode {
	case runExploit:
		sb.WriteString(r.exploitView())
	case runCheck:
		sb.WriteString(r.checkView())
	case runGen:
		sb.WriteString(r.genView())
	case runPrefix:
		sb.WriteString(r.prefixView())
	case runTitles:
		sb.WriteString(r.titlesView())
	}
	return sb.String()
}

// exploitView — счётчики + лента логов (таблицу SN→статус выпилили:
// захлёбывалась на сотнях серийников и перегружала экран; полный
// ход прогона теперь в ленте и в log.txt папки результатов).
// Прогресс — по УНИКАЛЬНЫМ серийникам (Progress), а не по Checked:
// дохлые (probe miss/404/туннель-фейл) тоже отмечаются — бар
// двигается на каждом исходе и добегает до 100%.
func (r *runState) exploitView() string {
	st := r.exp
	progress := st.Progress()
	pct := 0.0
	if st.Total > 0 {
		pct = float64(progress) / float64(st.Total) * 100
	}
	// снапы: зелёные успешные + красный счётчик фейлов (причины — в логе)
	snapStr := green(fmt.Sprint(atomic.LoadInt64(&st.Snaps)))
	if fails := atomic.LoadInt64(&st.SnapFails); fails > 0 {
		snapStr += red("/" + fmt.Sprint(fails))
	}
	var sb strings.Builder
	sb.WriteString(centerLine(fmt.Sprintf("%s %.1f%%", bar(progress, st.Total, 30), pct)) + "\n")
	sb.WriteString(centerLine(fmt.Sprintf("%d/%d | pwned: %s | added: %s | fail: %s | snap: %s | %s | %s",
		progress, st.Total,
		green(fmt.Sprint(atomic.LoadInt64(&st.Pwned))), yellow(fmt.Sprint(atomic.LoadInt64(&st.Added))), red(fmt.Sprint(atomic.LoadInt64(&st.Failed))),
		snapStr,
		fmt.Sprintf(tr("%.1f/сек"), st.Speed),
		r.elapsed())) + "\n\n")
	sb.WriteString(r.eventsBlock())
	return sb.String()
}

// titlesView — экран прогона «титры по списку»: бар по уникальным
// серийникам, счётчики titled/offline/fail, лента диагнозов.
func (r *runState) titlesView() string {
	st := r.ttl
	progress := st.Progress()
	pct := 0.0
	if st.Total > 0 {
		pct = float64(progress) / float64(st.Total) * 100
	}
	var sb strings.Builder
	sb.WriteString(centerLine(fmt.Sprintf("%s %.1f%%", bar(progress, st.Total, 30), pct)) + "\n")
	sb.WriteString(centerLine(fmt.Sprintf("%d/%d | titled: %s | off: %s | fail: %s | %s | %s",
		progress, st.Total,
		green(fmt.Sprint(atomic.LoadInt64(&st.Titled))), dim(fmt.Sprint(atomic.LoadInt64(&st.Offline))), red(fmt.Sprint(atomic.LoadInt64(&st.Failed))),
		fmt.Sprintf(tr("%.1f/сек"), st.Speed),
		r.elapsed())) + "\n\n")
	sb.WriteString(r.eventsBlock())
	return sb.String()
}

// eventsBlock — лента событий (check/prefix/gen), размер по высоте.
func (r *runState) eventsBlock() string {
	var sb strings.Builder
	sb.WriteString(centerLine(dim(tr("── логи ")+strings.Repeat("─", 48))) + "\n")
	var lines []string
	for _, ev := range r.events {
		lines = append(lines, ev)
	}
	sb.WriteString(centerBlock(lines))
	sb.WriteString("\n")
	if r.mode == runExploit && r.exp != nil && r.exp.Done {
		if inflight := atomic.LoadInt64(&r.exp.ExtrasInFlight); inflight > 0 {
			// прогресс дошёл до 100%, но снапы/титры ещё качаются —
			// esc сейчас прервёт их
			sb.WriteString(centerLine(yellow(fmt.Sprintf(
				tr("[i] снапы/титры в полёте: %d — esc прервёт их"), inflight))) + "\n")
			return sb.String()
		}
	}
	if r.finished() {
		sb.WriteString(centerLine(green("[+] готово")) + "\n")
	}
	return sb.String()
}

func (r *runState) checkView() string {
	st := r.chk
	pct := 0.0
	if st.Total > 0 {
		pct = float64(st.Checked) / float64(st.Total) * 100
	}
	var sb strings.Builder
	sb.WriteString(centerLine(fmt.Sprintf("%s %.1f%%", bar(st.Checked, st.Total, 30), pct)) + "\n")
	sb.WriteString(centerLine(fmt.Sprintf("%d/%d | alive: %s | dead: %s | %s | %s",
		st.Checked, st.Total,
		green(fmt.Sprint(st.Alive)), red(fmt.Sprint(st.Dead)),
		fmt.Sprintf(tr("%.0f/сек"), st.Speed),
		r.elapsed())) + "\n\n")
	sb.WriteString(r.eventsBlock())
	return sb.String()
}

func (r *runState) genView() string {
	written := atomic.LoadInt64(&r.genWritten)
	var sb strings.Builder
	sb.WriteString(centerLine(fmt.Sprintf("%s %s", bar(written, r.genTotal, 30),
		fmt.Sprintf(tr("%d/%d строк"), written, r.genTotal))) + "\n\n")
	sb.WriteString(centerLine(fmt.Sprintf(tr("файл: %s | %s"), r.genFile, r.elapsed())) + "\n\n")
	sb.WriteString(r.eventsBlock())
	return sb.String()
}

func (r *runState) prefixView() string {
	scanned := atomic.LoadInt64(&r.preScanned)
	found := atomic.LoadInt64(&r.preFound)
	var sb strings.Builder
	sb.WriteString(centerLine(fmt.Sprintf("%s %s", bar(scanned, int64(r.preTotal), 30),
		fmt.Sprintf(tr("%d/%d хостов"), scanned, r.preTotal))) + "\n")
	sb.WriteString(centerLine(fmt.Sprintf("%s | %s",
		fmt.Sprintf(tr("найдено SN: %s"), green(fmt.Sprint(found))), r.elapsed())) + "\n\n")
	sb.WriteString(r.eventsBlock())
	return sb.String()
}
