package fwd

// tunnel.go — сетевая часть из dh-fwd v2.0.0 (рекод), портирована в
// библиотечный пакет fwd: без CLI/UI/PortRegistry, с krushitel-хвостами
// (Ready/LocalPorts/Terminate) и хардендинг-гардами из старого fwd
// (короткие STUN-дейтаграммы, 0x17-фрейм <= 12 байт).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	BIND_TIMEOUT   = 10 * time.Second
	RETRY_ATTEMPTS = 3
	RETRY_DELAY    = 2 * time.Second
	CSEQ_BASE      = 100
	CSEQ_STEP      = 1000
)

var (
	HEARTBEAT_TIMEOUT  = 10 * time.Second
	RELAY_READ_TIMEOUT = 15 * time.Second
)

var errDeviceNotFound = errors.New("device response: code=404 Not Found")

// errCloudStall — облако/девайс молчит в хендшейке (любят глотать пакеты).
// Такой срыв НЕ тратит внешние попытки: Run() быстро рестартует попытку
// со свежими сокетами.
var errCloudStall = errors.New("cloud stall")

// Debug — глобальный тумблер протокольного дампа всех туннелей
// (probe/lookup/p2p-channel/STUN/realm — весь обмен с облаком).
var Debug bool

// LogHook — куда льют debug-строки (nil = fmt.Println на stderr).
var LogHook func(string)

// InitLimit — лимит одновременных P2P-инициализаций (handshake-фаз).
// Сотни туннелей, бьющие в облачный диспетчер одновременно, душат сами
// себя: датаграммы роняются, туннели ловят cloud stall. 0 = без лимита.
var InitLimit = 0

// StunFailHook вызывается один раз на попытку туннеля, когда STUN punch
// не пробился и data path откатывается на relay (медленный путь).
// nil = никто не слушает. Ставится драйвером (запись в nostun.txt).
var StunFailHook func(serial string)

var (
	initOnce sync.Once
	initSem  chan struct{}
)

// acquireInitSlot ждёт слот инициализации; false — туннель остановлен.
func (t *Tunnel) acquireInitSlot() bool {
	if InitLimit <= 0 {
		return true
	}
	initOnce.Do(func() { initSem = make(chan struct{}, InitLimit) })
	for {
		if t.isStopped() {
			return false
		}
		select {
		case initSem <- struct{}{}:
			return true
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (t *Tunnel) releaseInitSlot() {
	if InitLimit <= 0 || initSem == nil {
		return
	}
	select {
	case <-initSem:
	default:
	}
}

func isQuickRestart(err error) bool { return errors.Is(err, errCloudStall) }

// deviceAckTimeout — ожидание ack'ов в хендшейке: коротко, тишина =
// рестарт попытки, а не 15-секундный простой.
var deviceAckTimeout = 4 * time.Second

var ptcpHeartbeat = []byte{
	0x13, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

type PortSpec struct {
	Local  int
	Remote int
}

type Client struct {
	conn          net.Conn
	lastKeepalive time.Time
	cseq          int
	remotePort    int

	// Downstream coalescing: устройство стримит DATA-фреймы по 1280 байт;
	// запись каждого отдельным TCP-сегментом душит HTTP, объёмное видео
	// терпит. Батчим.
	flushMu    sync.Mutex
	pending    []byte
	flushTimer *time.Timer
}

const (
	coalesceDelay = 2 * time.Millisecond
	coalesceMax   = 16 * 1024
)

// writeAll дренирует буфер в conn целиком: net.Conn.Write может принять
// меньше байт, чем передано, и молча потерянный хвост корраптит поток.
func writeAll(conn net.Conn, b []byte) {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return
		}
		b = b[n:]
	}
}

// writeData буферизует даунстрим-фрагмент; сброс в сокет — по заполнению
// батча или через coalesceDelay.
func (c *Client) writeData(b []byte) {
	c.flushMu.Lock()
	c.pending = append(c.pending, b...)
	if len(c.pending) >= coalesceMax {
		out := c.pending
		c.pending = nil
		if c.flushTimer != nil {
			c.flushTimer.Stop()
			c.flushTimer = nil
		}
		c.flushMu.Unlock()
		writeAll(c.conn, out)
		return
	}
	if c.flushTimer == nil {
		c.flushTimer = time.AfterFunc(coalesceDelay, c.flushNow)
	}
	c.flushMu.Unlock()
}

// flushNow дренирует батч (колбек таймера или форсированный).
func (c *Client) flushNow() {
	c.flushMu.Lock()
	out := c.pending
	c.pending = nil
	c.flushTimer = nil
	c.flushMu.Unlock()
	if len(out) > 0 {
		writeAll(c.conn, out)
	}
}

type acceptConn struct {
	conn       net.Conn
	remotePort int
}

type specGroup struct {
	idxs  []int
	specs []PortSpec
}

// Tunnel владеет одним циклом соединения с устройством: облачный handshake,
// NAT-punch, PTCP-сессия и локальные TCP-листенеры, мультиплексированные
// поверх неё.
type Tunnel struct {
	serial, username, password, randsalt string
	dtype                                int
	debug                                bool
	useTCP                               bool // форс TCP-relay data path

	specs   []PortSpec
	specIdx []int

	deviceRemote *UDP
	mainRemote   *UDP
	primary      *UDP // data path: deviceRemote (direct) или mainRemote (relay)
	useTCPPath   bool // активный data path — TCP-relay канал
	tou          *touChannel
	listeners    []net.Listener
	clients      map[uint32]*Client
	clientsMu    sync.Mutex
	acceptCh     chan acceptConn
	done         chan struct{}
	cseqCounter  int

	ready      chan struct{} // закрывается, когда листенеры подняты
	localPorts map[int]int   // порт камеры → локальный порт

	// lastStage — фаза, на которой handshake прямо сейчас (текст для
	// диагностики «tunnel ready timeout»: без debug-дампов видно, где
	// туннель застрял). Под stageMu.
	stageMu   sync.Mutex
	lastStage string

	readerWG  sync.WaitGroup // readLoop/heartbeat/poolKeeper горутины
	bindMu    sync.Mutex
	bindWait  map[uint32]chan struct{}
	bindReqMu sync.Mutex // сериализует BIND-запросы
	socksMu   sync.Mutex // защищает сокеты/localPorts от конкурентного close
	stopped   bool       // Terminate(): не поднимать туннель заново
	errMu     sync.Mutex
	failErr   error

	// Пул realm'ов: пребинженные realm'ы на каждый форвард-порт. Веб-сервер
	// камеры рвёт HTTP-коннекты, браузер реконнектится на каждый запрос;
	// пребинженный realm убирает BIND round-trip из критического пути.
	// Кипер-горутина держит фиксированный уровень, in-flight бинды
	// учитываются, чтобы рефилл не проскакивал.
	poolMu     sync.Mutex
	pools      map[int]*poolState
	poolTarget int
}

// poolState — пул одного порта. Все поля под poolMu.
type poolState struct {
	queue    []uint32
	inflight int
}

func newTunnel(serial string, dtype int, username, password, randsalt string, debug, forceTCP bool, poolSize int, g specGroup) *Tunnel {
	t := &Tunnel{
		serial:      serial,
		dtype:       dtype,
		username:    username,
		password:    password,
		randsalt:    randsalt,
		debug:       debug,
		useTCP:      forceTCP,
		poolTarget:  poolSize,
		specs:       g.specs,
		specIdx:     g.idxs,
		cseqCounter: CSEQ_BASE,
	}
	t.reset()
	return t
}

// reset готовит новое поколение. readerWG.Wait() дренирует зомби-ридеров
// прошлой попытки, чтобы они не отравили новое состояние.
func (t *Tunnel) reset() {
	// Дренаж горутин прошлой попытки: без этого зомби readLoop проснётся
	// после reset и отравит свежую попытку, а зомби-heartbeat нас-PTCP-ит
	// в новые сокеты.
	t.readerWG.Wait()
	t.listeners = nil
	t.clients = make(map[uint32]*Client)
	t.acceptCh = make(chan acceptConn, 16)
	t.done = make(chan struct{})
	t.ready = make(chan struct{})
	t.cseqCounter = CSEQ_BASE
	t.socksMu.Lock()
	t.deviceRemote = nil
	t.mainRemote = nil
	t.tou = nil
	t.useTCPPath = false
	t.localPorts = nil
	t.socksMu.Unlock()
	t.primary = nil
	t.bindWait = make(map[uint32]chan struct{})
	t.pools = make(map[int]*poolState)
	t.failErr = nil
}

func (t *Tunnel) close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	for _, ln := range t.listeners {
		ln.Close()
	}
	t.clientsMu.Lock()
	for _, c := range t.clients {
		c.conn.Close()
	}
	t.clientsMu.Unlock()
	t.socksMu.Lock()
	dr, mr, tou := t.deviceRemote, t.mainRemote, t.tou
	t.socksMu.Unlock()
	if dr != nil {
		dr.Close()
	}
	if mr != nil {
		mr.Close()
	}
	if tou != nil {
		tou.close()
	}
}

// Terminate глушит туннель навсегда: runWithRetries больше не поднимает
// новые попытки.
func (t *Tunnel) Terminate() {
	t.errMu.Lock()
	t.stopped = true
	t.errMu.Unlock()
	t.close()
}

func (t *Tunnel) isStopped() bool {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.stopped
}

func (t *Tunnel) Run() error {
	// Слот init-фазы: handshake — самая тяжёлая часть (probe/lookup/
	// p2p-channel/STUN), ограничиваем одновременность по InitLimit.
	// Слот держит ТОЛЬКО handshake: прежний код не освобождал его после
	// успешного handshake вообще (defer с initDone), каждый туннель
	// навсегда занимал слот — после ~InitLimit туннелей за прогон все
	// новые висели в acquire («застрял на: wait») и умирали по
	// 45-секундному таймауту старта.
	if !t.acquireInitSlot() {
		return errors.New("tunnel stopped")
	}
	slotReleased := false
	releaseSlot := func() {
		if !slotReleased {
			slotReleased = true
			t.releaseInitSlot()
		}
	}
	defer releaseSlot()

	// Облако любит жрать пакеты: до 3 быстрых рестартов хендшейка со
	// свежими сокетами, НЕ тратя внешние попытки runWithRetries.
	const quickTries = 3
	var err error
	for i := 0; i < quickTries; i++ {
		err = t.handshake()
		if err == nil {
			break
		}
		t.close()
		if !isQuickRestart(err) {
			break
		}
		t.logf("cloud stall (%v) — quick restart %d/%d", err, i+1, quickTries)
		t.reset() // свежие сокеты/каналы для следующей попытки
	}
	if err != nil {
		t.close()
		return err
	}
	// handshake завершён — init-слот свободен, serve живёт без него
	releaseSlot()
	defer t.close()
	return t.serve()
}

// newMainRemote — (пере)создаёт главный облачный сокет: при рестартах
// старый закрывается, свежий кладётся в t.
func (t *Tunnel) newMainRemote() (*UDP, error) {
	m := NewUDP(MAIN_SERVER, MAIN_PORT, t.debug)
	m.debugLog = t.logf
	if m.initErr != nil {
		return nil, fmt.Errorf("main socket: %v", m.initErr)
	}
	t.socksMu.Lock()
	if t.mainRemote != nil {
		t.mainRemote.Close()
	}
	t.mainRemote = m
	t.socksMu.Unlock()
	return m, nil
}

// discover — Phase 1: online lookup через общий облачный мультиплексор
// (cloudmux). Отдельные сокеты на облако под нагрузкой глотались самим
// собой: 30 туннелей × 2 сокета на easy4ipcloud = шторм, облако
// замолкало. Мультиплексор держит один канал с ретранмитами.
// Тишина после бюджета = errCloudStall (быстрый рестарт Run).
func (t *Tunnel) discover() (*DHResponse, error) {
	mux, err := GetCloudMux()
	if err != nil {
		return nil, err
	}
	res, err := mux.Exchange("DHGET", fmt.Sprintf("/online/p2psrv/%s", t.serial), "", true, muxBudgetLookup)
	if err != nil {
		t.logf("online lookup silent: %v", err)
		return nil, fmt.Errorf("%w: online lookup silent (%v)", errCloudStall, err)
	}
	if res.Body["body/US"] == "" {
		return nil, fmt.Errorf("device %s not found on p2psrv", t.serial)
	}
	return res, nil
}

func (t *Tunnel) logf(format string, args ...any) {
	if !t.debug {
		return
	}
	// серийник в каждой строке: без него фазовые дампы разных туннелей
	// в общем логе не развесить
	msg := t.serial + ": " + fmt.Sprintf(format, args...)
	if LogHook != nil {
		LogHook(msg)
		return
	}
	fmt.Println(msg)
}

// setStage — отметка текущей фазы handshake (живёт независимо от debug:
// готовая диагностика для ошибки таймаута старта).
func (t *Tunnel) setStage(s string) {
	t.stageMu.Lock()
	t.lastStage = s
	t.stageMu.Unlock()
}

// Stage — последняя фаза туннеля ("wait" если ещё не начинал).
func (t *Tunnel) Stage() string {
	t.stageMu.Lock()
	defer t.stageMu.Unlock()
	if t.lastStage == "" {
		return "wait"
	}
	return t.lastStage
}

// Ready возвращает канал, закрываемый когда листенеры туннеля подняты.
func (t *Tunnel) Ready() <-chan struct{} { return t.ready }

// LocalPorts возвращает карту «порт камеры → локальный порт».
func (t *Tunnel) LocalPorts() map[int]int {
	t.socksMu.Lock()
	defer t.socksMu.Unlock()
	out := make(map[int]int, len(t.localPorts))
	for k, v := range t.localPorts {
		out[k] = v
	}
	return out
}

// Failure возвращает последнюю ошибку туннеля (если есть).
func (t *Tunnel) Failure() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.failErr
}

// p2pChannelBody собирает /device/<SN>/p2p-channel XML: Identify (8
// случайных байт через пробел), IpEncrpt флаг и (Type 1) подписанный
// зашифрованный auth-блок.
func p2pChannelBody(lport, dtype int, username, password, randsalt string, aid []byte) (string, []byte) {
	laddr := fmt.Sprintf("127.0.0.1:%d", lport)
	ipaddr := fmt.Sprintf("<IpEncrpt>true</IpEncrpt><LocalAddr>%s</LocalAddr>", laddr)
	authStr := ""
	var key []byte
	if dtype > 0 {
		key = getDeriveKey(username, password, randsalt)
		encNonce := getNonce()
		encLaddr := getEnc(key, encNonce, laddr)
		ipaddr = fmt.Sprintf("<IpEncrptV2>true</IpEncrptV2><LocalAddr>%s</LocalAddr>", encLaddr)
		authStr = getAuth(username, key, encNonce, laddr, randsalt)
	}

	aidHex := make([]string, 8)
	for i, b := range aid {
		aidHex[i] = fmt.Sprintf("%x", b)
	}

	body := fmt.Sprintf("<body>%s<Identify>%s</Identify>%s<version>5.0.0</version></body>",
		authStr, strings.Join(aidHex, " "), ipaddr)
	return body, key
}

// handshake — полный 4-фазный коннект: облачный discovery, аллокация
// relay-агента, Server Nat Info, inverted STUN punch и PTCP-неготиация.
// На успехе STUN t.primary = deviceRemote (direct), иначе mainRemote
// (relay agent).
func (t *Tunnel) handshake() error {
	// Phase 1: облачный discovery — через общий мультиплексор (см. discover)
	t.setStage("discover")
	res, err := t.discover()
	if err != nil {
		return err
	}
	us := res.Body["body/US"]
	t.setStage("relay lookup")
	t.logf("phase: discover ok (US=%s)", us)
	p2psrv := strings.SplitN(us, ":", 2)
	if len(p2psrv) != 2 || p2psrv[0] == "" {
		return fmt.Errorf("bad US address %q", us)
	}
	p2psrvPort, _ := strconv.Atoi(p2psrv[1])

	// Warm-up пробы на P2P-сервере устройства (US): fire-and-forget.
	// Ответы (/info — часто пустое Info, /probe — шум) ничего не решают:
	// раньше каждый Request блокировался на 15с чтения — под нагрузкой
	// туннель просто висел тут две трети хендшейка.
	p2psrvRemote := NewUDP(p2psrv[0], p2psrvPort, t.debug)
	p2psrvRemote.debugLog = t.logf
	p2psrvRemote.Request(fmt.Sprintf("/probe/device/%s", t.serial), "", true, false)
	p2psrvRemote.Request(fmt.Sprintf("/info/device/%s", t.serial), "", true, false)
	p2psrvRemote.Close()

	// Phase 2: lookup relay-диспетчера — через общий канал.
	t.logf("phase: relay lookup…")
	mux, err := GetCloudMux()
	if err != nil {
		return err
	}
	res, err = mux.Exchange("DHGET", "/online/relay", "", true, muxBudgetRelay)
	if err != nil {
		return fmt.Errorf("%w: relay lookup: %v", errCloudStall, err)
	}
	relay := strings.SplitN(res.Body["body/Address"], ":", 2)
	if len(relay) != 2 || relay[0] == "" {
		return fmt.Errorf("%w: relay address missing (%q)", errCloudStall, res.Body["body/Address"])
	}
	relayPort, _ := strconv.Atoi(relay[1])

	// Data-сокет для стороны устройства, пробитый через главный облачный хост.
	deviceRemote := NewUDP(MAIN_SERVER, MAIN_PORT, t.debug)
	deviceRemote.debugLog = t.logf
	t.socksMu.Lock()
	t.deviceRemote = deviceRemote
	t.socksMu.Unlock()
	if deviceRemote.initErr != nil {
		return fmt.Errorf("device socket: %v", deviceRemote.initErr)
	}

	// PTCP-сокет: облачные HTTP-фазы ушли в мультиплексор, этот сокет
	// живёт только relay-channel ack'ом и PTCP-трафиком (relay-путь).
	mainRemote, err := t.newMainRemote()
	if err != nil {
		return err
	}

	if t.dtype > 0 && (t.username == "" || t.password == "") {
		return fmt.Errorf("username and password required for type > 0")
	}

	// Phase 3: p2p-channel запрос со случайным 8-байтным session id (AID).
	aid := make([]byte, 8)
	rand.Read(aid)
	body, key := p2pChannelBody(deviceRemote.lport, t.dtype, t.username, t.password, t.randsalt, aid)

	deviceRemote.Request(fmt.Sprintf("/device/%s/p2p-channel", t.serial), body, true, false)

	// Аллокация relay-агента — на ДИСПЕТЧЕР релея (адрес из /online/relay),
	// не на главный хост: MAIN на /relay/agent отвечает пустым 200.
	// Идёт через mainRemote туннеля — как в dh-fwd v2.0.0.
	mainRemote.SetRemote(relay[0], relayPort)
	t.setStage("relay agent alloc")
	t.logf("phase: relay agent alloc…")
	res, err = mainRemote.Request("/relay/agent", "", true, true)
	if err != nil {
		return fmt.Errorf("%w: relay agent: %v", errCloudStall, err)
	}
	token := res.Body["body/Token"]
	agent := res.Body["body/Agent"]

	agentParts := strings.SplitN(agent, ":", 2)
	if len(agentParts) != 2 || agentParts[0] == "" {
		return fmt.Errorf("relay agent: bad agent %q", agent)
	}
	agentPort, _ := strconv.Atoi(agentParts[1])

	// Регистрация клиента на САМОМ АГЕНТЕ (agentParts, не диспетчер).
	mainRemote.SetRemote(agentParts[0], agentPort)
	if _, err = mainRemote.Request(fmt.Sprintf("/relay/start/%s", token), "<body><Client>:0</Client></body>", true, true); err != nil {
		t.logf("relay start silent (%v) — продолжаем, агент может подняться", err)
	}

	// Phase 4: Server Nat Info от устройства (через cloud/US). Облако и
	// девайс любят молчать: короткий таймаут + один повтор запроса,
	// тишина = errCloudStall (быстрый рестарт попытки, не 15с ожидания).
	t.setStage("device ack wait")
	t.logf("phase: p2p-channel sent, waiting device ack…")
	var ack *DHResponse
	for try := 0; try < 2; try++ {
		if try > 0 {
			t.logf("p2p-channel ack silent — повтор запроса")
			deviceRemote.Request(fmt.Sprintf("/device/%s/p2p-channel", t.serial), body, true, false)
		}
		ack, err = deviceRemote.Read(true, deviceAckTimeout)
		if err == nil && ack.Code < 200 {
			ack, err = deviceRemote.Read(true, deviceAckTimeout)
		}
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("%w: p2p-channel ack silent", errCloudStall)
	}
	res = ack
	if res.Code >= 400 {
		if res.Code == 404 {
			return errDeviceNotFound
		}
		if t.dtype == 0 && res.Code == 403 {
			return fmt.Errorf("device requires authentication")
		}
		return fmt.Errorf("device response: code=%d %s", res.Code, res.Status)
	}

	deviceLaddr := res.Body["body/LocalAddr"]
	devicePub := res.Body["body/PubAddr"]
	t.setStage("relay-channel")
	t.logf("phase: device ack ok code=%d LocalAddr=%q PubAddr=%q", res.Code, deviceLaddr, devicePub)

	if t.dtype > 0 {
		nonceStr := res.Body["body/Nonce"]
		if nonceStr != "" {
			nonceVal, _ := strconv.Atoi(nonceStr)
			deviceLaddr = getDec(key, nonceVal, deviceLaddr)
		}
	}

	devParts := strings.SplitN(devicePub, ":", 2)
	if len(devParts) != 2 || devParts[0] == "" {
		// камера ответила ack'ом без PubAddr — бывает на загруженном
		// облаке; ошибка вместо паники: runWithRetries перезапустит
		return fmt.Errorf("%w: device ack missing PubAddr (LocalAddr=%q)", errCloudStall, deviceLaddr)
	}
	devPort, _ := strconv.Atoi(devParts[1])
	deviceRemote.SetRemote(devParts[0], devPort)

	// Сообщаем устройству про relay-агента. Агент иногда ack'ает не сразу —
	// облако propagate'ит назначение релея несколько секунд: один повтор
	// на месте дешевле рестарта всего handshake.
	mainRemote.SetRemote(MAIN_SERVER, MAIN_PORT)
	authStr := ""
	if t.dtype > 0 {
		nonce2 := getNonce()
		authStr = getAuth(t.username, key, nonce2, "", t.randsalt)
	}
	sendRelayChannel := func() {
		mainRemote.Request(fmt.Sprintf("/device/%s/relay-channel", t.serial),
			fmt.Sprintf("<body>%s<agentAddr>%s:%d</agentAddr></body>", authStr, agentParts[0], agentPort),
			true, false)
	}
	sendRelayChannel()
	mainRemote.SetRemote(agentParts[0], agentPort)
	if _, err := mainRemote.Read(true, deviceAckTimeout); err != nil {
		t.logf("relay-channel ack silent (%v) — повтор запроса", err)
		mainRemote.SetRemote(MAIN_SERVER, MAIN_PORT)
		sendRelayChannel()
		mainRemote.SetRemote(agentParts[0], agentPort)
		if _, err2 := mainRemote.Read(true, deviceAckTimeout); err2 != nil {
			return fmt.Errorf("%w: relay-channel silent", errCloudStall)
		}
	}

	policy := res.Body["body/Policy"]
	tcpRelayAllowed := strings.Contains(policy, "tcprelay")

	// Форс TCP-relay: TOU-канал заменяет PTCP-over-UDP полностью.
	if t.useTCP {
		if err := t.attachTCPRelay(agentParts[0], agentPort, token); err != nil {
			return err
		}
		t.logf("TCP relay channel attached (forced)")
		return nil
	}

	// PTCP через relay: SYNC, затем token-запрос (0x17 -> 0x18).
	t.setStage("ptcp sync (relay)")
	t.logf("phase: ptcp sync over relay (policy tcprelay=%v)…", tcpRelayAllowed)
	mainRemote.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
	p, err := mainRemote.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		// UDP-relay путь мёртв — пробуем TCP-relay канал, если устройство
		// рекламирует tcprelay в списке политик.
		if tcpRelayAllowed {
			t.logf("ptcp sync over UDP failed (%v) — policy allows tcprelay, trying TCP relay", err)
			if aerr := t.attachTCPRelay(agentParts[0], agentPort, token); aerr == nil {
				t.logf("TCP relay channel attached (fallback)")
				return nil
			} else {
				t.logf("TCP relay fallback failed: %v", aerr)
			}
		}
		return fmt.Errorf("ptcp sync: %v", err)
	}

	mainRemote.RequestPTCP([]byte{
		0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	})
	p, err = mainRemote.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return fmt.Errorf("ptcp 0x17: %v", err)
	}
	// sign-токен начинается с 12-го байта тела (парити с dh-fwd):
	// короткий фрейм камеры (<=12) просто ждём дальше — иначе
	// p.Body[12:] паникует (slice bounds out of range).
	for len(p.Body) <= 12 {
		p, err = mainRemote.ReadPTCP(RELAY_READ_TIMEOUT)
		if err != nil {
			return fmt.Errorf("ptcp 0x17 wait: %v", err)
		}
	}
	sign := p.Body[12:]
	mainRemote.RequestPTCP(nil)
	t.setStage("stun punch")
	t.logf("phase: ptcp sign ok (%d bytes), stun punch…", len(sign))

	// Inverted STUN punch (Level 2): Init-пакет собирается из AID.
	invAid := make([]byte, 8)
	for i, b := range aid {
		invAid[i] = ^b
	}

	cookie := make([]byte, 4)
	rand.Read(cookie)
	transID := make([]byte, 12)
	rand.Read(transID)

	eaddr := make([]byte, 6)
	binary.BigEndian.PutUint16(eaddr[0:2], uint16(devPort))
	copy(eaddr[2:], net.ParseIP(devParts[0]).To4())
	for i, b := range eaddr {
		eaddr[i] = ^b
	}

	stunInit := []byte{0xFF, 0xFE, 0xFF, 0xE7}
	stunInit = append(stunInit, cookie...)
	stunInit = append(stunInit, transID...)
	stunInit = append(stunInit, []byte{0x7F, 0xD5, 0xFF, 0xF7}...)
	stunInit = append(stunInit, invAid...)
	stunInit = append(stunInit, []byte{0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE}...)
	stunInit = append(stunInit, eaddr...)

	localIPStr, localPortStr, _ := strings.Cut(deviceLaddr, ":")
	localPortVal, _ := strconv.Atoi(localPortStr)

	t.logf(":%d >>> %s:%d (LocalAddr)", deviceRemote.lport, localIPStr, localPortVal)
	t.logf(":%d >>> %s:%d (PubAddr)", deviceRemote.lport, devParts[0], devPort)

	deviceRemote.SendTo(stunInit, &net.UDPAddr{IP: net.ParseIP(localIPStr), Port: localPortVal})
	deviceRemote.Send(stunInit)

	var stunResponse []byte
	deviceRemote.SetTimeout(2 * time.Second)
	deadline := time.Now().Add(10 * time.Second)
	attempt := 0

	for time.Now().Before(deadline) {
		data, addr, err := deviceRemote.RecvFrom(4096)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				attempt++
				if attempt <= 2 {
					t.logf("Retransmit STUN init (attempt %d)", attempt)
					deviceRemote.Send(stunInit)
				}
				continue
			}
			break
		}
		if len(data) < 4 {
			continue
		}
		magic := data[:4]
		t.logf("STUN <<< %s magic=%x len=%d", addr, magic, len(data))

		if string(magic) == "\xFE\xFE\xFF\xE7" {
			stunResponse = data
			t.logf("Got STUN response (fefeffe7)")
			break
		} else if string(magic) == "\xFF\xFE\xFF\xE7" {
			if len(data) < 40 {
				continue
			}
			t.logf("Got device cross-STUN init (fffeffe7), responding...")
			resp := make([]byte, 0, 40)
			resp = append(resp, []byte{0xFE, 0xFE, 0xFF, 0xE7}...)
			resp = append(resp, data[4:8]...)
			resp = append(resp, data[8:20]...)
			resp = append(resp, []byte{0x7F, 0xD6, 0xFF, 0xF7}...)
			resp = append(resp, invAid...)
			resp = append(resp, []byte{0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE}...)
			resp = append(resp, data[34:40]...)
			deviceRemote.SendTo(resp, addr)
			t.logf("STUN >>> %s response sent", addr)
		} else {
			t.logf("Unknown magic: %x", magic)
		}
	}

	if stunResponse == nil {
		t.logf("STUN failed — using relay agent as the data path")
		if StunFailHook != nil {
			StunFailHook(t.serial)
		}
		t.setStage("ready (relay)")
		t.primary = mainRemote
		return nil
	}

	// Подтверждение прямого канала бурстом из 5 Binding Confirm.
	confirm := []byte{0xFE, 0xFE, 0xFF, 0xF3}
	confirm = append(confirm, cookie...)
	confirm = append(confirm, transID...)
	confirm = append(confirm, []byte{0x7F, 0xD6, 0xFF, 0xF7}...)
	confirm = append(confirm, invAid...)

	for range 5 {
		t.logf("Confirm >>>")
		deviceRemote.Send(confirm)
	}

	time.Sleep(300 * time.Millisecond)
	deviceRemote.SetTimeout(500 * time.Millisecond)
	for {
		data, addr, err := deviceRemote.RecvFrom(4096)
		if err != nil {
			break
		}
		t.logf("Drain <<< %s magic=%x len=%d", addr, data[:4], len(data))
	}
	deviceRemote.SetTimeout(0)

	// Direct-путь: полный PTCP auth-handshake с sign-токеном.
	if err := ptcpHandshake(deviceRemote, sign); err != nil {
		return fmt.Errorf("ptcp device handshake: %v", err)
	}
	t.logf("PTCP handshake complete (direct)")
	t.setStage("ready (direct)")
	t.primary = deviceRemote
	return nil
}

// attachTCPRelay диалит relay-агента по TCP и ставит TOU-канал активным
// data path.
func (t *Tunnel) attachTCPRelay(agentHost string, agentPort int, token string) error {
	ch, err := dialTCPRelay(agentHost, agentPort, token, t.debug, t.logf)
	if err != nil {
		return err
	}
	t.socksMu.Lock()
	t.tou = ch
	t.useTCPPath = true
	t.socksMu.Unlock()
	return nil
}

// ptcpHandshake гоняет SYNC -> AUTH_REQ(0x19+sign) -> AUTH_RESP(0x1A) ->
// AUTH_FINAL(0x1B) с пиром на сокете u.
func ptcpHandshake(u *UDP, signToken []byte) error {
	u.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
	p, err := u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	if string(p.Body) != "\x00\x03\x01\x00" {
		return fmt.Errorf("ptcp sync mismatch")
	}

	pkt := append([]byte{0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, signToken...)
	u.RequestPTCP(pkt)
	p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	for len(p.Body) == 0 {
		p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
		if err != nil {
			return err
		}
	}
	if p.Body[0] != 0x1A {
		return fmt.Errorf("ptcp auth mismatch: got 0x%02x", p.Body[0])
	}

	u.RequestPTCP([]byte{0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	if len(p.Body) != 0 {
		return fmt.Errorf("ptcp final expected empty")
	}
	return nil
}

// serve открывает локальные листенеры и качает трафик, пока туннель жив.
func (t *Tunnel) serve() error {
	type okListen struct {
		idx    int
		port   int
		remote int
	}
	oks := []okListen{}
	for i, spec := range t.specs {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", spec.Local))
		if err != nil {
			t.logf("listen :%d failed: %v", spec.Local, err)
			continue
		}
		port := spec.Local
		if port == 0 {
			if addr, ok := ln.Addr().(*net.TCPAddr); ok {
				port = addr.Port
			}
		}
		t.listeners = append(t.listeners, ln)
		oks = append(oks, okListen{idx: t.specIdx[i], port: port, remote: spec.Remote})
		go t.acceptLoop(ln, spec.Remote)
	}
	if len(t.listeners) == 0 {
		return fmt.Errorf("no listeners available for tunnel")
	}

	// Карта «порт камеры → локальный порт» — до close(ready).
	ports := make(map[int]int, len(oks))
	for _, o := range oks {
		ports[o.remote] = o.port
	}
	t.socksMu.Lock()
	t.localPorts = ports
	t.socksMu.Unlock()
	close(t.ready)

	if t.primary != nil {
		t.primary.lastRecv = time.Now()
	}

	done := t.done
	if t.useTCPPath {
		t.readerWG.Add(2)
		go t.touReadLoop(done)
		go t.touHeartbeatLoop(done)
	} else {
		t.readerWG.Add(3)
		go t.readLoop(done, t.deviceRemote)
		go t.readLoop(done, t.mainRemote)
		go t.heartbeatLoop(done)
		// Киперы пула realm'ов: держат пребинженные realm'ы на каждый
		// форвард-порт, чтобы волна браузерных коннектов не платила
		// BIND round-trip.
		t.readerWG.Add(len(oks))
		for _, o := range oks {
			t.poolMu.Lock()
			t.pools[o.remote] = &poolState{}
			t.poolMu.Unlock()
			go t.poolKeeper(done, o.remote)
		}
	}

	for {
		select {
		case <-t.done:
			t.readerWG.Wait()
			return t.Failure()
		case ac := <-t.acceptCh:
			go t.handleBind(ac)
		}
	}
}

// readLoop вычитывает PTCP-фреймы из одного сокета. done — токен поколения,
// захваченный при спавне: после reset горутина обязана выйти молча.
func (t *Tunnel) readLoop(done chan struct{}, u *UDP) {
	defer t.readerWG.Done()
	for {
		select {
		case <-done:
			return
		default:
		}

		p, err := u.ReadPTCP(5 * time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if u == t.primary && time.Since(u.LastRecv()) > HEARTBEAT_TIMEOUT {
					t.fail(fmt.Errorf("heartbeat timeout: no PTCP on primary socket for %v", HEARTBEAT_TIMEOUT))
					return
				}
				continue
			}
			// Если наше поколение уже закрыто — это зомби-пробуждение
			// («use of closed network connection»); не травим следующую
			// попытку своей ошибкой.
			select {
			case <-done:
			default:
				t.fail(err)
			}
			return
		}
		t.routePTCP(p, u)
	}
}

// touReadLoop вычитывает TOU-фреймы из TCP-relay канала.
func (t *Tunnel) touReadLoop(done chan struct{}) {
	defer t.readerWG.Done()
	t.socksMu.Lock()
	ch := t.tou
	t.socksMu.Unlock()
	if ch == nil {
		return
	}
	for {
		select {
		case <-done:
			return
		default:
		}
		typ, session, payload, _, err := ch.readFrame(time.Now().Add(tcpRelayFrameTimeout))
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(ch.LastRecv()) > HEARTBEAT_TIMEOUT {
					t.fail(fmt.Errorf("tcp relay heartbeat timeout: no TOU frames for %v", HEARTBEAT_TIMEOUT))
					return
				}
				continue
			}
			select {
			case <-done:
			default:
				t.fail(err)
			}
			return
		}
		switch typ {
		case touTypeData:
			if c := t.getClient(session); c != nil && len(payload) > 0 {
				c.writeData(payload)
			}
		case touTypeSyn:
			// Удалённое открытие сессии — ACK по TOU-конвенции.
			ch.writeAck(session, 0)
			t.logf("tcp-relay: remote SYN session=%#010x, ACK sent", session)
		case touTypeAck, touTypeKA, touTypeSrv:
			// liveness трекается через LastRecv
		default:
			t.logf("tcp-relay: frame type=0x%02x (ignored)", typ)
		}
	}
}

// touHeartbeatLoop держит живыми TCP-relay канал и клиентские сессии.
func (t *Tunnel) touHeartbeatLoop(done chan struct{}) {
	defer t.readerWG.Done()
	hb := time.NewTicker(tcpRelayKeepaliveEvery)
	defer hb.Stop()
	for {
		select {
		case <-done:
			return
		case <-hb.C:
			t.socksMu.Lock()
			ch := t.tou
			t.socksMu.Unlock()
			if ch == nil {
				return
			}
			if err := ch.writeKeepalive(0); err != nil {
				t.fail(fmt.Errorf("tcp relay keepalive: %v", err))
				return
			}
			now := time.Now()
			t.clientsMu.Lock()
			for rid, c := range t.clients {
				if now.Sub(c.lastKeepalive) > 25*time.Second && c.remotePort == 554 {
					ka := fmt.Sprintf("OPTIONS * RTSP/1.0\r\nCSeq: %d\r\n\r\n", c.cseq)
					t.writeRealmData(rid, []byte(ka))
					c.cseq++
					c.lastKeepalive = now
				}
			}
			t.clientsMu.Unlock()
		}
	}
}

func (t *Tunnel) heartbeatLoop(done chan struct{}) {
	defer t.readerWG.Done()
	hb := time.NewTicker(5 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-done:
			return
		case <-hb.C:
			t.socksMu.Lock()
			mr := t.mainRemote
			t.socksMu.Unlock()
			if mr != nil {
				mr.RequestPTCP([]byte{})
			}
			if t.primary != nil {
				t.primary.RequestPTCP(ptcpHeartbeat)
			}

			now := time.Now()
			t.clientsMu.Lock()
			for rid, c := range t.clients {
				// Keepalive-байты льём только в RTSP-realm'ы: OPTIONS —
				// мусор протокола внутри DVRIP (37777) или HTTP (80).
				// PTCP-heartbeat держит сам туннель.
				if now.Sub(c.lastKeepalive) > 25*time.Second && c.remotePort == 554 {
					ka := fmt.Sprintf("OPTIONS * RTSP/1.0\r\nCSeq: %d\r\n\r\n", c.cseq)
					t.writeRealmData(rid, []byte(ka))
					c.cseq++
					c.lastKeepalive = now
				}
			}
			t.clientsMu.Unlock()
		}
	}
}

func (t *Tunnel) acceptLoop(ln net.Listener, remotePort int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case t.acceptCh <- acceptConn{conn: conn, remotePort: remotePort}:
		case <-t.done:
			conn.Close()
			return
		}
	}
}

// popRealm берёт пребинженный realm для порта, если есть.
func (t *Tunnel) popRealm(remotePort int) (uint32, bool) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	st := t.pools[remotePort]
	if st == nil || len(st.queue) == 0 {
		return 0, false
	}
	r := st.queue[0]
	st.queue = st.queue[1:]
	return r, true
}

func (t *Tunnel) pushRealm(remotePort int, realm uint32) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	st := t.pools[remotePort]
	if st == nil || len(st.queue) >= t.poolTarget {
		return
	}
	st.queue = append(st.queue, realm)
}

// dropRealm убирает realm из пула (устройство его скинуло).
func (t *Tunnel) dropRealm(realm uint32) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	for _, st := range t.pools {
		for i, r := range st.queue {
			if r == realm {
				st.queue = append(st.queue[:i], st.queue[i+1:]...)
				return
			}
		}
	}
}

// preBindRealm открывает один realm и паркует его в пул.
func (t *Tunnel) preBindRealm(remotePort int) {
	t.poolMu.Lock()
	st := t.pools[remotePort]
	if st == nil || t.poolTarget <= 0 ||
		len(st.queue)+st.inflight >= t.poolTarget {
		t.poolMu.Unlock()
		return
	}
	st.inflight++
	t.poolMu.Unlock()

	defer func() {
		t.poolMu.Lock()
		st.inflight--
		t.poolMu.Unlock()
	}()

	realmID := rand.Uint32()
	wait := make(chan struct{})
	t.setBindWait(realmID, wait)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	t.bindReqMu.Lock()
	t.primary.RequestPTCP(bindPkt)
	time.Sleep(3 * time.Millisecond)
	t.bindReqMu.Unlock()

	select {
	case <-wait:
		t.pushRealm(remotePort, realmID)
		t.logf("Realm pool: pre-bound realm=%#010x port=%d", realmID, remotePort)
	case <-time.After(BIND_TIMEOUT):
		t.takeBindWait(realmID)
	case <-t.done:
		t.takeBindWait(realmID)
	}
}

// poolKeeper держит фиксированный уровень пребинженных realm'ов для порта.
func (t *Tunnel) poolKeeper(done chan struct{}, remotePort int) {
	defer t.readerWG.Done()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			t.poolMu.Lock()
			st := t.pools[remotePort]
			if st == nil {
				t.poolMu.Unlock()
				return
			}
			spawn := t.poolTarget - len(st.queue) - st.inflight
			if spawn < 0 {
				spawn = 0
			}
			t.poolMu.Unlock()
			for i := 0; i < spawn; i++ {
				go t.preBindRealm(remotePort)
			}
		}
	}
}

// ── virtPipe: буферизованный дуплексный пайп ─────────────────────────
// net.Pipe синхронный (Write блокирует до чтения peer'а) — на стриминге
// с push-фреймами камеры это мёртвые локи. Эта пара связных «сокетов»
// буферизована: Write никогда не блокирует, Read ждёт данные/дедлайн.

type virtHalf struct {
	mu       sync.Mutex
	peer     *virtHalf
	buf      []byte
	closed   bool
	deadline time.Time
	wake     chan struct{}
}

func newVirtPipe() (*virtHalf, *virtHalf) {
	a := &virtHalf{wake: make(chan struct{}, 1)}
	b := &virtHalf{wake: make(chan struct{}, 1)}
	a.peer, b.peer = b, a
	return a, b
}

func (h *virtHalf) push(b []byte) {
	h.mu.Lock()
	h.buf = append(h.buf, b...)
	h.mu.Unlock()
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

func (h *virtHalf) Read(b []byte) (int, error) {
	for {
		h.mu.Lock()
		if len(h.buf) > 0 {
			n := copy(b, h.buf)
			h.buf = h.buf[n:]
			h.mu.Unlock()
			return n, nil
		}
		if h.closed {
			h.mu.Unlock()
			return 0, io.EOF
		}
		h.peer.mu.Lock()
		peerClosed := h.peer.closed
		h.peer.mu.Unlock()
		if peerClosed {
			// peer закрылся, буфер пуст — данных больше не будет
			h.mu.Unlock()
			return 0, io.EOF
		}
		deadline := h.deadline
		h.mu.Unlock()

		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(d)
			select {
			case <-h.wake:
				timer.Stop()
			case <-timer.C:
				return 0, os.ErrDeadlineExceeded
			}
			continue
		}
		<-h.wake
	}
}

func (h *virtHalf) Write(b []byte) (int, error) {
	h.mu.Lock()
	closed := h.closed
	h.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	h.peer.push(b)
	return len(b), nil
}

func (h *virtHalf) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.mu.Unlock()
	// будим ОБЕ стороны: читатели h видят closed→EOF, читатели peer'а —
	// тоже (его Write'ы больше не имеют смысла)
	select {
	case h.wake <- struct{}{}:
	default:
	}
	h.peer.mu.Lock()
	p := h.peer.closed
	h.peer.mu.Unlock()
	if !p {
		select {
		case h.peer.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (h *virtHalf) SetDeadline(t time.Time) error {
	h.mu.Lock()
	h.deadline = t
	h.mu.Unlock()
	return nil
}

func (h *virtHalf) SetReadDeadline(t time.Time) error  { return h.SetDeadline(t) }
func (h *virtHalf) SetWriteDeadline(t time.Time) error { return h.SetDeadline(t) }

func (h *virtHalf) LocalAddr() net.Addr  { return virtAddr{} }
func (h *virtHalf) RemoteAddr() net.Addr { return virtAddr{} }

type virtAddr struct{}

func (virtAddr) Network() string { return "p2p" }
func (virtAddr) String() string  { return "camera-via-tunnel" }

// DialCamera — p2pwn-стиль: «соединение» с портом камеры через туннель
// БЕЗ локального TCP-листенера. Возвращает net.Conn (буферизованный
// виртуальный сокет): Write уходит в realm (сегментируясь), Read — из
// realm. Закрытие коннекта гасит realm DISC'ом на камере. Для TOU-пути
// realm открывается SYN'ом.
func (t *Tunnel) DialCamera(remotePort int) (net.Conn, error) {
	server, client := newVirtPipe()

	// туннель мог умереть/рестартнуть до нас: primary уже nil
	if t.primary == nil || t.isStopped() {
		server.Close()
		client.Close()
		return nil, fmt.Errorf("tunnel is down")
	}

	if t.useTCPPath {
		realmID := rand.Uint32()
		t.addClient(realmID, server, remotePort)
		t.socksMu.Lock()
		ch := t.tou
		t.socksMu.Unlock()
		if ch == nil {
			server.Close()
			client.Close()
			return nil, fmt.Errorf("tou channel is nil")
		}
		if err := ch.write(touBuildSyn(realmID)); err != nil {
			t.delClient(realmID)
			server.Close()
			client.Close()
			return nil, fmt.Errorf("tcp-relay SYN failed: %w", err)
		}
		return client, nil
	}

	var realmID uint32
	if id, ok := t.popRealm(remotePort); ok {
		realmID = id
		t.logf("Realm pool: hit realm=%#010x port=%d", realmID, remotePort)
	} else {
		realmID = rand.Uint32()
	}

	wait := make(chan struct{})
	t.setBindWait(realmID, wait)
	t.addClient(realmID, server, remotePort)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	// primary может обнулиться смертью/рестартом туннеля прямо под нами —
	// снимаем локально и проверяем внутри bindReqMu
	t.bindReqMu.Lock()
	p := t.primary
	if p == nil {
		t.bindReqMu.Unlock()
		t.takeBindWait(realmID)
		t.delClient(realmID)
		server.Close()
		client.Close()
		return nil, fmt.Errorf("tunnel is down (mid-bind)")
	}
	p.RequestPTCP(bindPkt)
	time.Sleep(10 * time.Millisecond)
	t.bindReqMu.Unlock()

	select {
	case <-wait:
		t.logf("DialCamera: bind OK realm=%#010x port=%d", realmID, remotePort)
		return client, nil
	case <-time.After(BIND_TIMEOUT):
		t.takeBindWait(realmID)
		t.delClient(realmID)
		server.Close()
		client.Close()
		return nil, fmt.Errorf("bind timeout port=%d", remotePort)
	case <-t.done:
		t.takeBindWait(realmID)
		client.Close()
		return nil, fmt.Errorf("tunnel closed")
	}
}

// handleBind открывает один realm: случайный id, BIND-фрейм, ждём STATUS OK.
// В TCP-relay режиме realm — TOU-сессия, открытая SYN-фреймом.
// На UDP-пути предпочтение пребинженному realm из пула: без ожидания BIND.
func (t *Tunnel) handleBind(ac acceptConn) {
	if !t.useTCPPath {
		if realmID, ok := t.popRealm(ac.remotePort); ok {
			t.logf("Realm pool: hit realm=%#010x port=%d", realmID, ac.remotePort)
			t.addClient(realmID, ac.conn, ac.remotePort)
			return
		}
	}

	realmID := rand.Uint32()
	t.logf("Binding realm=%#010x port=%d", realmID, ac.remotePort)

	if t.useTCPPath {
		t.addClient(realmID, ac.conn, ac.remotePort)
		t.socksMu.Lock()
		ch := t.tou
		t.socksMu.Unlock()
		if ch == nil {
			ac.conn.Close()
			t.delClient(realmID)
			return
		}
		if err := ch.write(touBuildSyn(realmID)); err != nil {
			t.logf("tcp-relay SYN failed realm=%#010x: %v", realmID, err)
			t.delClient(realmID)
			ac.conn.Close()
			return
		}
		t.logf("tcp-relay: SYN sent for session=%#010x (port %d)", realmID, ac.remotePort)
		return
	}

	wait := make(chan struct{})
	t.setBindWait(realmID, wait)

	t.addClient(realmID, ac.conn, ac.remotePort)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(ac.remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	bindStart := time.Now()
	t.bindReqMu.Lock()
	if t.primary == nil {
		// туннель умер между accept и BIND — прибираемся
		t.bindReqMu.Unlock()
		t.takeBindWait(realmID)
		t.delClient(realmID)
		ac.conn.Close()
		return
	}
	t.primary.RequestPTCP(bindPkt)
	time.Sleep(10 * time.Millisecond)
	t.bindReqMu.Unlock()

	select {
	case <-wait:
		t.logf("Bind OK realm=%#010x in %v", realmID, time.Since(bindStart))
	case <-time.After(BIND_TIMEOUT):
		t.logf("Bind FAILED realm=%#010x port=%d", realmID, ac.remotePort)
		t.delClient(realmID)
		ac.conn.Close()
		t.takeBindWait(realmID)
	case <-t.done:
		t.takeBindWait(realmID)
		ac.conn.Close()
	}
}

func (t *Tunnel) setBindWait(realmID uint32, ch chan struct{}) {
	t.bindMu.Lock()
	t.bindWait[realmID] = ch
	t.bindMu.Unlock()
}

func (t *Tunnel) takeBindWait(realmID uint32) chan struct{} {
	t.bindMu.Lock()
	defer t.bindMu.Unlock()
	ch := t.bindWait[realmID]
	delete(t.bindWait, realmID)
	return ch
}

func (t *Tunnel) addClient(realmID uint32, conn net.Conn, remotePort int) {
	t.clientsMu.Lock()
	t.clients[realmID] = &Client{
		conn:          conn,
		lastKeepalive: time.Now(),
		cseq:          t.cseqCounter,
		remotePort:    remotePort,
	}
	t.cseqCounter += CSEQ_STEP
	t.clientsMu.Unlock()
	go t.clientReader(conn, realmID)
}

func (t *Tunnel) getClient(realmID uint32) *Client {
	t.clientsMu.Lock()
	defer t.clientsMu.Unlock()
	return t.clients[realmID]
}

func (t *Tunnel) delClient(realmID uint32) {
	t.clientsMu.Lock()
	delete(t.clients, realmID)
	t.clientsMu.Unlock()
}

// dataSegmentMax повторяет сегментацию самого устройства из капчура
// (1316-байтные дейтаграммы = 1280-байтные DATA-полезные нагрузки):
// кадры крупнее триггерят IP-фрагментацию и повышают потери.
const dataSegmentMax = 1280

// writeRealmData пушит одну realm-нагрузку в активный data path,
// сегментируя до wire-безопасных размеров.
func (t *Tunnel) writeRealmData(realm uint32, data []byte) {
	for len(data) > 0 {
		n := len(data)
		if n > dataSegmentMax {
			n = dataSegmentMax
		}
		chunk := data[:n]
		if t.useTCPPath {
			t.socksMu.Lock()
			ch := t.tou
			t.socksMu.Unlock()
			if ch == nil {
				return
			}
			ch.writeData(realm, chunk)
		} else if t.primary != nil {
			t.primary.RequestPTCP((&PTCPPayload{Realm: realm, Payload: chunk}).Bytes())
		}
		data = data[n:]
	}
}

// clientReader качает локальные TCP-байты в туннель как realm-DATA.
func (t *Tunnel) clientReader(conn net.Conn, realmID uint32) {
	buf := make([]byte, 16*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if !t.useTCPPath {
				discPkt := make([]byte, 16)
				discPkt[0] = 0x12
				binary.BigEndian.PutUint32(discPkt[4:8], realmID)
				copy(discPkt[12:], "DISC")
				t.primary.RequestPTCP(discPkt)
			}
			t.logf("Disconnected realm=%#010x", realmID)
			t.delClient(realmID)
			return
		}
		t.writeRealmData(realmID, buf[:n])
	}
}

// routePTCP диспетчит один входящий PTCP-фрейм. Пустые тела — чистые ACK
// пира — зеркалим. DATA-фреймы получают коалесцированный ack (ScheduleAck).
func (t *Tunnel) routePTCP(p *PTCP, src *UDP) {
	if len(p.Body) == 0 {
		src.RequestPTCP(nil)
		return
	}
	src.ScheduleAck()

	switch p.Body[0] {
	case 0x10:
		pl, err := ParsePTCPPayload(p.Body)
		if err != nil {
			return
		}
		if c := t.getClient(pl.Realm); c != nil && len(pl.Payload) > 0 {
			c.writeData(pl.Payload)
		}
	case 0x12:
		if len(p.Body) < 8 {
			// короткий 0x12-фрейм (пир шлёт и 4-байтовые) — без realm
			// в теле разбирать нечего
			return
		}
		realm := binary.BigEndian.Uint32(p.Body[4:8])
		if ch := t.takeBindWait(realm); ch != nil {
			close(ch)
			return
		}
		t.dropRealm(realm) // устройство скинуло пребинженный realm
		if c := t.getClient(realm); c != nil {
			c.conn.Close()
			t.delClient(realm)
			t.logf("DVR DISC realm=%#010x", realm)
		}
	case 0x13:
		// Пирский heartbeat — liveness трекается через lastRecv.
	case 0x0a:
		// Flow-control / ping от устройства или relay-агента; no-op.
	default:
		var sincePrimary float64
		if t.primary != nil {
			sincePrimary = time.Since(t.primary.LastRecv()).Seconds()
		}
		srcStr := "secondary"
		if src == t.primary {
			srcStr = "primary"
		}
		t.logf("PTCP type=%#04x len=%d src=%s sincePrimary=%.2fs time=%s hex=%x",
			p.Body[0], len(p.Body), srcStr, sincePrimary, time.Now().Format("15:04:05.000"), p.Body)
		if len(p.Body) >= 12 {
			tryRealm := binary.BigEndian.Uint32(p.Body[4:8])
			payload := p.Body[12:]
			if len(payload) > 0 && len(payload) <= 4096 {
				if c := t.getClient(tryRealm); c != nil {
					t.logf("Forwarding type 0x%02x as data to realm=%#010x (%d bytes)", p.Body[0], tryRealm, len(payload))
					c.writeData(payload)
				}
			}
		}
	}
}

func (t *Tunnel) fail(err error) {
	t.errMu.Lock()
	if t.failErr == nil {
		t.failErr = err
	}
	t.errMu.Unlock()
	select {
	case <-t.done:
	default:
		close(t.done)
	}
}

// runWithRetries крутит попытки до успеха или до исчерпания RETRY_ATTEMPTS.
// Ничего не печатает: ошибки уходят в callback. Прекращается навсегда после
// Terminate().
func runWithRetries(t *Tunnel, onExhausted func(err error)) {
	for attempt := 1; ; attempt++ {
		if t.isStopped() {
			return
		}
		err := t.Run()
		if err == nil {
			return
		}
		if t.isStopped() {
			return
		}
		if errors.Is(err, errDeviceNotFound) || attempt > RETRY_ATTEMPTS {
			if onExhausted != nil {
				onExhausted(err)
			}
			return
		}
		time.Sleep(RETRY_DELAY)
		t.reset()
	}
}
