// Package i18n — локализация RU/EN. Русские строки — ключи: при lang=ru
// Tr() возвращает ключ как есть (исходники не меняются), при lang=en —
// перевод из словаря. Словарь = фриз-лист: только строки из утверждённой
// таблицы, ничего лишнего.
package i18n

var lang = "ru"

// SetLang выставляет язык ("ru" / "en"); прочие значения = ru.
func SetLang(l string) {
	if l == "en" {
		lang = "en"
		return
	}
	lang = "ru"
}

// Lang — текущий язык.
func Lang() string { return lang }

// en — англ. словарь. Ключи — точные русские строки из исходников.
var en = map[string]string{
	// ── баннер ──
	"крушитель v1": "krushitel v1",

	// ── меню + выход ──
	"что сегодня делаем?": "what are we doing today?",
	"крушим)":             "crush some cams)",
	"генерируем SN с списка префиксов": "generate SNs from prefix list",
	"сканим серийники":                 "scan serials",
	"расшифровываем .xml от smartpss":  "decrypt smartpss .xml",
	"ищем префиксы":                    "find prefixes",
	"настройки":                        "settings",
	"ошибка: %v":                       "error: %v",
	"↑↓ навигация  ·  enter / цифра — выбор  ·  q — выход":                      "↑↓ navigate  ·  enter / digit — select  ·  q — quit",
	"↑↓ навигация  ·  enter / цифра — выбор  ·  esc — назад  ·  q — выход":      "↑↓ navigate  ·  enter / digit — select  ·  esc — back  ·  q — quit",
	"↑↓ навигация  ·  enter/пробел — переключить  ·  esc — назад  ·  q — выход": "↑↓ navigate  ·  enter/space — toggle  ·  esc — back  ·  q — quit",

	// ── smartpss-подменю ──
	"расшифровать XML (SmartPSS export → креды)": "decrypt XML (SmartPSS export → creds)",
	"расшифровать blob (base64 → пароль)":        "decrypt blob (base64 → password)",
	"назад": "back",

	// ── настройки + редактор титров ──
	"снапы (%s)":                    "snapshots (%s)",
	"автозамена титров (%s)":        "title replace (%s)",
	"   └ канал (ChannelTitle): %s": "   └ channel (ChannelTitle): %s",
	"   └ OSD слот %d: %s":          "   └ OSD slot %d: %s",
	"(пусто)":                       "(empty)",
	"титры":                         "titles",
	"впиши сюда что-то, что будут видеть все:":             "write something everyone will see:",
	"! до %d символов ! пусто — поле не используется !":    "! up to %d chars ! if empty - field will be unused !",
	"ограничение: максимум %d символов (у тебя %d)":        "limit: max %d chars (you have %d)",
	"текст канала (ChannelTitle)":                          "channel text (ChannelTitle)",
	"текст OSD-слота %d (CustomTitle)":                     "OSD slot %d text (CustomTitle)",
	"enter — сохранить  ·  esc — назад  ·  ctrl+c — выход": "enter — save  ·  esc — back  ·  ctrl+c — quit",

	// ── редактор dummy-кредов ──
	"добавить нового юзера":              "add dummy creds",
	"dummy-креды":                        "dummy creds",
	"новый юзер в формате login:passwd:": "new user as login:passwd:",
	"нужен формат login:passwd":          "need login:passwd format",
	"лог-режим (%s)":                     "log mode (%s)",

	// ── формы ──
	"обязательное поле":                                       "required field",
	"такого файла нет! перепиши, пожалуйста":                  "no such file! fix it, please",
	"y/n — да/нет · enter — далее · q — выход · esc — в меню": "y/n — yes/no · enter — next · q — quit · esc — menu",
	"enter — далее · esc — в меню · ctrl+c — выход":           "enter — next · esc — menu · ctrl+c — quit",
	"[да]":  "[yes]",
	"[нет]": "[no]",
	"вкл":   "on",
	"выкл":  "off",
	"нужна кое какая информация":       "need some info",
	"файл с серийниками (targets.txt)": "serials file (targets.txt)",
	"папка для результатов":            "results folder",
	"потоков":      "threads",
	"снапы?":       "snapshots?",
	"генерация sn": "sn generation",
	"файл с префиксами (10 символов)": "prefix file (10 chars)",
	"выходной файл":                   "output file",
	"нет префиксов в файле (нужно >= 10 символов, берутся первые 10)": "no prefixes in file (need >= 10 chars, first 10 are used)",
	"файл будет весить больше 50 мб (%dмб). продолжать?":              "file will exceed 50 mb (%dmb). continue?",
	"[!] Отмена.":        "[!] cancel.",
	"скан sn":            "sn scan",
	"файл с серийниками": "serials file",
	"выходной файл (только онлайн)":                                       "output file (online only)",
	"файл %s уже есть (%d строк). дописать в конец? (нет = перезаписать)": "file %s already exists (%d lines). append? (no = overwrite)",
	"xml → креды": "xml → creds",
	"файл с результатами (SmartPSS export)": "results file (SmartPSS export)",
	"название файла для кредов":             "creds output filename",
	"[!] нет декодированных кредов":         "[!] no decoded creds",
	"[+] %d кред(ов) -> %s":                 "[+] %d creds -> %s",
	"blob → пароль":                         "blob → password",
	"вставь base64 blob":                    "paste base64 blob",
	"   пароль: ":                           "   password: ",
	"префиксы":                              "prefixes",
	"IP цели или файл со списком хостов":    "target IP or host list file",
	"порт": "port",
	"выходной файл (база, без расширения)": "output file (base, no extension)",
	"[-] папка не создается: ":             "[-] can't create folder: ",
	"[-] файл без хостов :(":               "[-] file has no hosts :(",
	"[+] серийников: %d, префиксов: %d":    "[+] serials: %d, prefixes: %d",
	"  модель: ":   "  model: ",
	"  прошивка: ": "  firmware: ",

	// ── экран прогона ──
	"[+] готово":     "[+] done",
	"%.1f/сек":       "%.1f/sec",
	"%.0f/сек":       "%.0f/sec",
	"── логи ":       "── logs ",
	"%d/%d строк":    "%d/%d lines",
	"файл: %s | %s":  "file: %s | %s",
	"%d/%d хостов":   "%d/%d hosts",
	"найдено SN: %s": "found SNs: %s",
	"esc/b — стоп и в меню  ·  q — выход":         "esc/b — stop & menu  ·  q — quit",
	"esc/b — в меню  ·  q — выход":                "esc/b — menu  ·  q — quit",
	"туннель: перезапуск демона (попытка %d)":     "tunnel: daemon restart (attempt %d)",
	"туннель: поднят с %d-й попытки":              "tunnel: up on attempt %d",
	"туннель: попытка %d не удалась (%v)":         "tunnel: attempt %d failed (%v)",
	"[+] ре-очередь: %d серийников вторым кругом": "[+] re-queue: %d serials, second pass",

	// ── движок exploit ──
	"Ошибка чтения входного файла: ":      "input file read error: ",
	"Ошибка открытия входного файла: ":    "input file open error: ",
	"Ошибка создания выходного файла: ":   "output file creation error: ",
	"Ошибка открытия results.txt: ":       "results.txt open error: ",
	"Ошибка открытия done.txt: ":          "done.txt open error: ",
	"Ошибка открытия nostun.txt: ":        "nostun.txt open error: ",
	"Ошибка создания папки результатов: ": "results folder creation error: ",
	"Файл пуст":                            "file is empty",
	"Dummy-креды: ":                        "dummy creds: ",
	"dummy_login: длина %d, нужно 5-32":    "dummy_login: length %d, need 5-32",
	"dummy_login: только латиница и цифры": "dummy_login: latin and digits only",
	"dummy_pass: длина %d, нужно 8-32":     "dummy_pass: length %d, need 8-32",
	"dummy_pass: только латиница и цифры":  "dummy_pass: latin and digits only",
	"пречек":              "precheck",
	"облако не ответило":  "cloud silent",
	"туннель…":            "tunnel…",
	"туннель ✓":           "tunnel ✓",
	"туннель ✗":           "tunnel ✗",
	"туннель не поднялся": "tunnel failed",
	"%s — туннель ок":     "%s — tunnel ok",
	"%s — OnvifUser пуст или не подошёл, пробуем CVE-2024-39943": "%s — OnvifUser empty/failed check, trying CVE-2024-39943",
	"%s — креды не подошли, пробуем dummy":                       "%s — creds failed check, trying dummy",
	"проверка кредов":                                            "creds check",
	"%s — dummy добавлен (CVE-2024-39943) %s:%s":                 "%s — dummy added (CVE-2024-39943) %s:%s",
	"%s — не вышло":                                              "%s — failed",
	"%s — титры включены, но все поля пустые":                    "%s — titles on, but all fields empty",
	"%s — титры (OSD): %q (подтверждено)":                        "%s — titles (OSD): %q (confirmed)",
	"%s — титры (канал): %v":                                     "%s — titles (channel): %v",
	"%s — титры (OSD): отправлены без подтверждения (камера рестартует OSD)": "%s — titles (OSD): sent unconfirmed (camera restarts OSD)",
	"%s — титры (OSD): %v": "%s — titles (OSD): %v",
	"%s — снап: туннель умер (рестарт OSD после титров?)": "%s — snap: tunnel dead (OSD restart after titles?)",
	"%s — снап не вышел: %s":                              "%s — snap failed: %s",
	"%s — STUN не пробился, туннель через relay":          "%s — STUN failed, tunnel via relay",
	"[i] снапы/титры в полёте: %d — esc прервёт их":       "[i] snaps/titles in flight: %d — esc will cut them",

	// ── подменю «титры по списку» ──
	"титры по списку":                              "titles by list",
	"файл с камерами (results.txt)":                "cameras file (results.txt)",
	"[!] пропущено строк мимо формата: %d":         "[!] skipped malformed lines: %d",
	"%s — offline (%v)":                            "%s — offline (%v)",
	"%s — титры (канал): %v — пробуем NetKeyboard": "%s — titles (channel): %v — trying NetKeyboard",
	"%s — титры (канал): не прошли (%v)":           "%s — titles (channel): failed (%v)",
	"%s — титры поставлены":                        "%s — titles applied",
	"титры: все поля пустые (настройки → тексты)":  "titles: all fields empty (settings → texts)",

	// ── движок scanner ──
	"Ошибка открытия выходного файла: ":                                   "output file open error: ",
	"Ошибка резолва сервера: ":                                            "server resolve error: ",
	"не смог создать необходимое кол-во сокетов (фикс: ulimit -n 100000)": "couldn't create enough UDP sockets (to fix: ulimit -n 100000)",

	"подождите %d сек…":   "wait %d sec…",
	"enter / пробел — ок": "enter / space — ok",
}

// Tr — перевод строки по словарю; при ru (или отсутствии ключа) — как есть.
func Tr(s string) string {
	if lang == "en" {
		if v, ok := en[s]; ok {
			return v
		}
	}
	return s
}
