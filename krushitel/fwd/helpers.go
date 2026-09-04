package fwd

// helpers.go — крипто (Type 1 auth), PTCP wire format, DH HTTP parsing и
// UDP-обёртка из dh-fwd v2.0.0: глубокие кольца приёма/отправки,
// кумулятивные ack-и, окно приёма 64KB вместо счётчика.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Облачные эндпоинты и креды стоковых клиентов (публичные, зашиты в каждый
// официальный клиент Dahua: SmartPSS, DMSS, gDMSS).
const (
	MAIN_SERVER = "www.easy4ipcloud.com"
	MAIN_PORT   = 8800

	WSSE_USERNAME = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	WSSE_USERKEY  = "996103384cdf19179e19243e959bbf8b"
	DEFAULT_SALT  = ""
	AES_IV        = "2z52*lk9o6HRyJrf"
)

var (
	cseqLock sync.Mutex
	cseq     uint32
)

// ---------------------------------------------------------------------------
// Device auth (Type 1): вывод мастер-ключа, AES-OFB шифрование адреса,
// HMAC-SHA256 подпись запросов. Зеркало раздела 4.3 спецификации DH-P2P.
// ---------------------------------------------------------------------------

// getDeriveKey строит 32-символьный uppercase-hex MD5 мастер-ключ:
//
//	MD5(user + ":Login to " + salt + ":" + pass), отрендеренный ASCII-hex.
func getDeriveKey(username, password, randsalt string) []byte {
	salt := randsalt
	if salt == "" {
		salt = DEFAULT_SALT
	}
	sum := md5.Sum([]byte(fmt.Sprintf("%s:Login to %s:%s", username, salt, password)))
	return []byte(fmt.Sprintf("%X", sum))
}

// getNonce возвращает случайный int32 для соли PBKDF2.
func getNonce() int {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<31))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// deriveDK разворачивает мастер-ключ: PBKDF2-HMAC-SHA256(key, decimal(nonce), 20000, 32).
func deriveDK(key []byte, nonce int) []byte {
	salt := []byte(strconv.Itoa(nonce))
	return pbkdf2.Key(key, salt, 20000, 32, sha256.New)
}

// getEnc шифрует LocalAddr AES-128-OFB на производном ключе и фиксированном
// IV, отдаёт Base64. Раздел 4.3 шаг 3 спецификации.
func getEnc(key []byte, nonce int, data string) string {
	dk := deriveDK(key, nonce)
	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(AES_IV))
	out := make([]byte, len(data))
	stream.XORKeyStream(out, []byte(data))
	return base64.StdEncoding.EncodeToString(out)
}

// getDec обращает getEnc: расшифровывает зашифрованный LocalAddr устройства.
func getDec(key []byte, nonce int, data string) string {
	dk := deriveDK(key, nonce)
	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(AES_IV))
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return data
	}
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return string(out)
}

// getAuth собирает DevAuth XML-блок: Base64(HMAC-SHA256(masterKey,
// string(nonce) + string(unixNow) + payload)). Раздел 4.3 шаг 4.
func getAuth(username string, key []byte, nonce int, payload, randsalt string) string {
	salt := randsalt
	if salt == "" {
		salt = DEFAULT_SALT
	}
	curdate := time.Now().Unix()
	msg := []byte(fmt.Sprintf("%d%d%s", nonce, curdate, payload))
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	auth := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf(
		"<CreateDate>%d</CreateDate><DevAuth>%s</DevAuth><Nonce>%d</Nonce><RandSalt>%s</RandSalt><UserName>%s</UserName>",
		curdate, auth, nonce, salt, username,
	)
}

// Hardcoded devinfo-крипто, recovered из P2PDll.dll
// (CP2PClientImpl::parseDeviceInfo): поле "Info" из /info/device/<SN> —
// это Base64(AES-256-OFB(JSON)).
const (
	DEVINFO_KEY = "kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf" // 32 байта, AES-256
	DEVINFO_IV  = "MydvJw*Iw1w&i^kk"                 // 16 байт IV
)

// decryptDevInfoInfo расшифровывает base64 AES-256-OFB поле "Info".
func decryptDevInfoInfo(field string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(field))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(DEVINFO_KEY))
	if err != nil {
		return nil, err
	}
	stream := cipher.NewOFB(block, []byte(DEVINFO_IV))
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return out, nil
}

// ---------------------------------------------------------------------------
// PTCP wire format (Level 3). 24-байтный big-endian заголовок:
// "PTCP" | Rlid | Llid | Pid | Lmid | Rmid, затем тело.
// ---------------------------------------------------------------------------

// PTCPPayload — мультиплексированный по realm DATA-фрагмент (тип тела 0x10).
type PTCPPayload struct {
	Realm   uint32
	Payload []byte
}

func (p *PTCPPayload) Bytes() []byte {
	length := len(p.Payload) | 0x10000000
	buf := make([]byte, 12+len(p.Payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(length))
	binary.BigEndian.PutUint32(buf[4:8], p.Realm)
	binary.BigEndian.PutUint32(buf[8:12], 0)
	copy(buf[12:], p.Payload)
	return buf
}

func ParsePTCPPayload(data []byte) (*PTCPPayload, error) {
	if len(data) < 12 {
		return nil, errors.New("packet too short")
	}
	length := binary.BigEndian.Uint32(data[0:4])
	realm := binary.BigEndian.Uint32(data[4:8])
	pad := binary.BigEndian.Uint32(data[8:12])
	if pad != 0 {
		return nil, errors.New("invalid padding")
	}
	length &= 0xFFFF
	body := data[12:]
	if len(body) != int(length) {
		return nil, errors.New("invalid length")
	}
	return &PTCPPayload{Realm: realm, Payload: body}, nil
}

// PTCP — полный транспортный фрейм.
type PTCP struct {
	Rlid uint32 // ack байт-отправлено пира
	Llid uint32 // ack байт-получено локально
	Pid  uint32 // package id (SYNC-маркер или 0x0000FFFF - счётчик)
	Lmid uint32 // локальный счётчик сообщений
	Rmid uint32 // эхо пира Lmid
	Body []byte
}

func (p *PTCP) Bytes() []byte {
	buf := make([]byte, 24+len(p.Body))
	copy(buf[0:4], "PTCP")
	binary.BigEndian.PutUint32(buf[4:8], p.Rlid)
	binary.BigEndian.PutUint32(buf[8:12], p.Llid)
	binary.BigEndian.PutUint32(buf[12:16], p.Pid)
	binary.BigEndian.PutUint32(buf[16:20], p.Lmid)
	binary.BigEndian.PutUint32(buf[20:24], p.Rmid)
	copy(buf[24:], p.Body)
	return buf
}

func ParsePTCP(data []byte) (*PTCP, error) {
	if len(data) < 24 {
		return nil, errors.New("packet too short")
	}
	if string(data[0:4]) != "PTCP" {
		return nil, errors.New("invalid magic")
	}
	return &PTCP{
		Rlid: binary.BigEndian.Uint32(data[4:8]),
		Llid: binary.BigEndian.Uint32(data[8:12]),
		Pid:  binary.BigEndian.Uint32(data[12:16]),
		Lmid: binary.BigEndian.Uint32(data[16:20]),
		Rmid: binary.BigEndian.Uint32(data[20:24]),
		Body: data[24:],
	}, nil
}

// ---------------------------------------------------------------------------
// DH HTTP-over-UDP (Level 1) парсинг ответов.
// ---------------------------------------------------------------------------

type DHResponse struct {
	Version string
	Code    int
	Status  string
	Headers map[string]string
	Body    map[string]string
}

func ParseDHResponse(data string) *DHResponse {
	parts := strings.SplitN(data, "\r\n\r\n", 2)
	headPart := parts[0]
	bodyPart := ""
	if len(parts) > 1 {
		bodyPart = strings.TrimSpace(parts[1])
	}

	lines := strings.Split(headPart, "\r\n")
	statusParts := strings.SplitN(lines[0], " ", 3)
	code, _ := strconv.Atoi(statusParts[1])

	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if hd := strings.SplitN(line, ": ", 2); len(hd) == 2 {
			headers[hd[0]] = hd[1]
		}
	}

	resp := &DHResponse{
		Version: statusParts[0],
		Code:    code,
		Status:  strings.Join(statusParts[2:], " "),
		Headers: headers,
	}
	if bodyPart != "" {
		resp.Body = parseXML(bodyPart)
	}
	return resp
}

// parseXML разворачивает <body> XML-документ в "path/to/tag" -> text.
func parseXML(data string) map[string]string {
	result := make(map[string]string)
	decoder := xml.NewDecoder(strings.NewReader(data))
	var stack []string

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && len(stack) > 0 {
				result[strings.Join(stack, "/")] = text
			}
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// UDP-обёртка. Каждый сокет программы создаётся через NewUDP: форс udp4 и
// отключение SIO_UDP_CONNRESET на Windows (без этого прошлая ICMP
// port-unreachable травит следующий read ошибкой WSAECONNRESET).
// ---------------------------------------------------------------------------

type UDP struct {
	conn *net.UDPConn

	initErr error

	lhost string
	lport int

	rhost string
	rport int

	raddr *net.UDPAddr
	debug bool

	ptcpMu    sync.Mutex
	ptcpSent  uint32
	ptcpRecv  uint32
	ptcpCount uint32
	ptcpID    uint32
	rmid      uint32

	ackFrames uint32
	lastAck   time.Time

	rxMu     sync.Mutex
	rxBuf    []byte // переиспользуемый буфер приёма (один читатель на сокет)
	deadline time.Time

	lastRecv time.Time
	debugLog func(format string, args ...any)
}

const udpRxMax = 65535

var udpListenCfg = net.ListenConfig{Control: udpControl}

func NewUDP(host string, port int, debug bool) *UDP {
	u := &UDP{rhost: host, rport: port, debug: debug, rxBuf: make([]byte, udpRxMax)}
	pc, err := udpListenCfg.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		u.initErr = err
		return u
	}
	conn := pc.(*net.UDPConn)
	local := conn.LocalAddr().(*net.UDPAddr)

	// Глубокие кольца приёма/отправки: камера стримит ~1280-байтные сегменты
	// на wire rate; маленький kernel-буфер переполняется на всплесках
	// планировщика, и RTO-ретрансмиты устройства схлопывают пропускную.
	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(1 * 1024 * 1024)

	u.conn = conn
	u.lhost = local.IP.String()
	u.lport = local.Port

	if host != "" {
		u.raddr, err = net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			u.initErr = err
		}
	}
	return u
}

func (u *UDP) String() string { return fmt.Sprintf(":%d", u.lport) }

func (u *UDP) Close() {
	if u.conn != nil {
		u.conn.Close()
	}
}

func (u *UDP) SetRemote(host string, port int) {
	u.rhost = host
	u.rport = port
	u.raddr, _ = net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
}

func (u *UDP) Send(data []byte) {
	if u.conn != nil && u.raddr != nil {
		u.conn.WriteTo(data, u.raddr)
	}
}

func (u *UDP) SendTo(data []byte, addr *net.UDPAddr) {
	if u.conn != nil {
		u.conn.WriteTo(data, addr)
	}
}

func (u *UDP) Recv(bufsize int, timeout time.Duration) ([]byte, error) {
	if u.conn == nil {
		if u.initErr != nil {
			return nil, u.initErr
		}
		return nil, fmt.Errorf("udp socket is not initialized")
	}

	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	u.rxMu.Lock()
	defer u.rxMu.Unlock()
	for {
		if timeout > 0 {
			u.conn.SetReadDeadline(deadline)
		} else {
			u.conn.SetReadDeadline(time.Time{})
		}
		n, _, err := u.conn.ReadFromUDP(u.rxBuf)
		if err == nil {
			u.lastRecv = time.Now()
			// Zero-copy: возвращаемый срез алиасит rxBuf и валиден до
			// следующего Recv на этом сокете. Потребители ReadPTCP
			// обрабатывают фреймы синхронно (routePTCP), так что ничего не
			// удерживает его. RecvFrom продолжает копировать, потому что
			// STUN-handshake держит буферы между чтениями.
			return u.rxBuf[:n], nil
		}
		// Windows может отравить unconnected-сокет WSAECONNRESET после
		// прошлой отправки в закрытый порт; считаем шумом и читаем дальше
		// до истечения дедлайна.
		if isConnReset(err) && timeout > 0 && time.Now().Before(deadline) {
			continue
		}
		return nil, err
	}
}

func (u *UDP) RecvFrom(bufsize int) ([]byte, *net.UDPAddr, error) {
	if u.conn == nil {
		return nil, nil, fmt.Errorf("udp socket is not initialized")
	}
	u.rxMu.Lock()
	defer u.rxMu.Unlock()
	if !u.deadline.IsZero() {
		_ = u.conn.SetReadDeadline(u.deadline)
	} else {
		_ = u.conn.SetReadDeadline(time.Time{})
	}
	n, addr, err := u.conn.ReadFromUDP(u.rxBuf)
	if err != nil {
		if isConnReset(err) {
			return nil, addr, err
		}
		return nil, nil, err
	}
	u.lastRecv = time.Now()
	out := make([]byte, n)
	copy(out, u.rxBuf[:n])
	return out, addr, nil
}

func (u *UDP) LastRecv() time.Time { return u.lastRecv }

func (u *UDP) logf(format string, args ...any) {
	if u.debugLog != nil {
		u.debugLog(format, args...)
		return
	}
	fmt.Printf(format+"\n", args...)
}

func (u *UDP) SetTimeout(d time.Duration) {
	if u.conn == nil {
		return
	}
	if d > 0 {
		u.deadline = time.Now().Add(d)
		_ = u.conn.SetReadDeadline(u.deadline)
	} else {
		u.deadline = time.Time{}
		_ = u.conn.SetReadDeadline(time.Time{})
	}
}

// Read ждёт один DH HTTP-ответ.
func (u *UDP) Read(returnError bool, timeout time.Duration) (*DHResponse, error) {
	data, err := u.Recv(4096, timeout)
	if err != nil {
		return nil, err
	}

	if u.debug {
		u.logf(":%d <<< %s:%d\n%s", u.lport, u.rhost, u.rport, string(data))
	}

	res := ParseDHResponse(string(data))
	if !returnError && res.Code >= 400 {
		return nil, fmt.Errorf("error %d: %s", res.Code, res.Status)
	}
	if u.debug {
		u.logf("Parsed <<< code=%d status=%s", res.Code, res.Status)
	}
	return res, nil
}

// clockOffset — поправка локальных часов, снятая с Date-заголовка облака.
// WSSE Created должен совпадать с серверным временем, иначе облако отвечает
// 401 Unauthorized с <Error>TimeOut</Error> (уехавшие часы машины).
var (
	clockOnce   sync.Once
	clockOffset time.Duration
)

// serverTimeSync пробует облако один раз (без auth — любой ответ несёт
// Date) и запоминает перекос локальных часов.
func serverTimeSync(u *UDP) {
	if _, err := u.Request("/probe/p2psrv", "", false, false); err != nil {
		return
	}
	data, err := u.Recv(4096, 3*time.Second)
	if err != nil {
		return
	}
	res := ParseDHResponse(string(data))
	if res == nil {
		return
	}
	if d, ok := res.Headers["Date"]; ok {
		for _, layout := range []string{"2006-01-02T15:04:05Z", time.RFC1123, time.RFC1123Z} {
			if tt, err := time.Parse(layout, d); err == nil {
				clockOffset = tt.UTC().Sub(time.Now().UTC())
				break
			}
		}
	}
}

func ensureClockSync(u *UDP) {
	clockOnce.Do(func() { serverTimeSync(u) })
}

// nowUTC — сервер-корректированное время для WSSE Created.
func nowUTC() time.Time {
	return time.Now().UTC().Add(clockOffset)
}

// buildDHRequest сериализует одну DHGET/DHPOST транзакцию с WSSE cloud
// auth-заголовками (общая для UDP-транспорта и TCP-relay бинда).
func buildDHRequest(method, path, body string, auth bool, myCseq uint32) []byte {
	nonce, _ := rand.Int(rand.Reader, big.NewInt(1<<31))
	curdate := nowUTC().Format("2006-01-02T15:04:05Z")
	pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, curdate, WSSE_USERNAME, WSSE_USERKEY)

	h := sha1.New()
	h.Write([]byte(pwd))
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\nCSeq: %d\r\n", method, path, myCseq))
	if auth {
		sb.WriteString(fmt.Sprintf(
			"Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%d\", Created=\"%s\"\r\n",
			WSSE_USERNAME, digest, nonce, curdate,
		))
	}
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: \r\nContent-Length: %d\r\n", len(body)))
	}
	sb.WriteString(fmt.Sprintf("\r\n%s", body))
	return []byte(sb.String())
}

// Request отправляет одну DHGET/DHPOST транзакцию с WSSE cloud auth.
func (u *UDP) Request(path, body string, auth, shouldRead bool) (*DHResponse, error) {
	cseqLock.Lock()
	cseq++
	myCseq := cseq
	cseqLock.Unlock()

	method := "DHGET"
	if body != "" {
		method = "DHPOST"
	}

	req := buildDHRequest(method, path, body, auth, myCseq)

	if u.debug {
		u.logf(":%d >>> %s:%d\n%s", u.lport, u.rhost, u.rport, string(req))
	}

	u.Send(req)

	if shouldRead {
		return u.Read(false, RELAY_READ_TIMEOUT)
	}
	return nil, nil
}

const (
	// Ack-коалесинг (TCP-style delayed ack): камера стримит тысячи
	// 1280-байтных DATA-фреймов в секунду; ack каждого отдельно удваивает
	// датаграммный rate и жрёт апстрим на связках chatty+bulk. Кумулятивные
	// байт-ack-и (Llid) делают delayed ack безопасными.
	ackEvery = 4
	ackDelay = 10 * time.Millisecond
)

// ScheduleAck шлёт один чистый ACK-фрейм на ackEvery принятых фреймов или
// ackDelay, что раньше. Любой исходящий фрейм тоже несёт кумулятивный ack,
// так что ничего не теряется от ожидания.
func (u *UDP) ScheduleAck() {
	u.ptcpMu.Lock()
	u.ackFrames++
	flush := u.ackFrames >= ackEvery || time.Since(u.lastAck) >= ackDelay
	if flush {
		u.ackFrames = 0
		u.lastAck = time.Now()
	}
	u.ptcpMu.Unlock()
	if flush {
		u.RequestPTCP(nil)
	}
}

// ReadPTCP ждёт один PTCP-фрейм и обновляет ack/rmid состояние.
func (u *UDP) ReadPTCP(timeout time.Duration) (*PTCP, error) {
	data, err := u.Recv(4096, timeout)
	if err != nil {
		return nil, err
	}
	ptcp, err := ParsePTCP(data)
	if err != nil {
		return nil, err
	}

	u.ptcpMu.Lock()
	// Llid — настоящий кумулятивный ack байт, принятых ОТ пира (оригинал
	// строит его из счётчика принятого каналом, +0x3c). Подмешивание
	// Rlid пира давало бугущий монотонный счётчик.
	u.ptcpRecv += uint32(len(ptcp.Body))
	u.rmid = ptcp.Lmid
	u.ptcpMu.Unlock()

	return ptcp, nil
}

// RequestPTCP сериализует и шлёт один PTCP-фрейм, двигая счётчики.
// Пустое тело — чистый ACK. Тело SYNC получает специальный Pid.
//
// Семантика Pid на проводе: младшие 16 бит = окно приёма, которое мы
// рекламируем, старшие 16 бит = флаги (SYN=0x0002). Мы дреним сразу,
// поэтому всегда рекламируем полное окно 64KB — счётчик-окно, которое
// сжималось, троттлило длинные видео-сессии, потому что устройство
// честно соблюдает flow control.
func (u *UDP) RequestPTCP(body []byte) {
	u.ptcpMu.Lock()
	defer u.ptcpMu.Unlock()

	isSync := len(body) == 4 && body[0] == 0x00 && body[1] == 0x03 && body[2] == 0x01 && body[3] == 0x00

	pid := uint32(0x0000FFFF)
	if isSync {
		pid = 0x0002FFFF
	}

	ptcp := &PTCP{
		Rlid: u.ptcpSent,
		Llid: u.ptcpRecv,
		Pid:  pid,
		Lmid: u.ptcpID,
		Rmid: u.rmid,
		Body: body,
	}

	u.ptcpSent += uint32(len(body))
	u.ptcpID++
	if !isSync && len(body) > 0 {
		u.ptcpCount++
	}

	u.Send(ptcp.Bytes())
}

func GetInvertedBytes(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = ^b
	}
	return out
}
