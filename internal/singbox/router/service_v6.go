package router

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/hoaxisr/awg-manager/internal/singbox/router/bypassset"
	"github.com/hoaxisr/awg-manager/internal/storage"
	sysiptables "github.com/hoaxisr/awg-manager/internal/sys/iptables"
)

// Сервисная половина v6-слоя (правила и хук — в iptables6.go).
//
// Слой ведомый: он живёт только внутри режима tproxy и только пока тот
// установлен. Решения «включён ли роутер», «жив ли движок», «какая метка у
// политики» принимает v4-путь — сюда они приходят готовыми. Отказ слоя не
// роняет ни enable, ни Reconcile: IPv4-перехват важнее и должен пережить и
// отсутствующий ip6tables, и роутер без IPv6. Причина отказа уходит в журнал.

// v6WantState — что настройки хотят от v6-слоя на этом тике.
type v6WantState int

const (
	// v6Off — слой выключен настройкой.
	v6Off v6WantState = iota
	// v6On — слой включён, спек собран.
	v6On
	// v6Unknown — слой включён, но топологию роутера снять не удалось. Не
	// «выключить», а «на этом тике ничего не трогать»: иначе транзиентный
	// отказ чтения снёс бы рабочие правила и инбаунды.
	v6Unknown
)

// v6ReloadWait — сколько ждём привязки v6-инбаундов после правки конфига,
// прежде чем отложить установку правил до следующего тика.
const v6ReloadWait = 10 * time.Second

// ip6tablesAvailable — шов над проверкой наличия ip6tables.
var ip6tablesAvailable = sysiptables.Available6

// ensureBypassSet6 / dropBypassSet6 — швы над набором AWGM-BYPASS6.
//
// Набором владеет v6-слой, а не общий путь geoip-обхода: правила ip6tables,
// которые на него ссылаются, ставит и снимает только слой, а снести набор
// можно лишь после них («set is in use by a kernel component»). Наполняет его
// общий проход bypassset.Populate — вместе с IPv4-набором.
var (
	ensureBypassSet6 = func(ctx context.Context) error {
		if err := bypassset.EnsureXtSetModule(ctx); err != nil {
			return fmt.Errorf("загрузка xt_set: %w", err)
		}
		if bypassset.IPSetBinary() == "" {
			return bypassset.ErrIPSetNotAvailable
		}
		return bypassset.CreateSet6(ctx)
	}
	// Дамп — ПЕРВЫМ, как в teardownBypassSet: хук netfilter.d пересоздаёт
	// набор из дампа, если набора нет, и сработавший между сносом набора и
	// удалением дампа хук воскресил бы его до перезагрузки.
	dropBypassSet6 = func(ctx context.Context) error {
		var err error
		if rerr := os.Remove(bypassSave6Path); rerr != nil && !os.IsNotExist(rerr) {
			err = rerr
		}
		if bypassset.IPSetBinary() != "" {
			err = errors.Join(err, bypassset.DestroySet6(ctx))
		}
		return err
	}
)

// v6Warn пишет предупреждение слоя в журнал, но не повторяет одно и то же
// каждые 30 секунд: reconcile тикает постоянно, а причина (нет IPv6 на LAN,
// мост без порта) держится часами. v6Clear снимает запомненное сообщение.
func (s *ServiceImpl) v6Warn(msg string) {
	if s.v6LastWarn == msg {
		return
	}
	s.v6LastWarn = msg
	s.v6Problem.Store(&msg)
	s.appLog.Warn("ipv6", "", msg)
}

func (s *ServiceImpl) v6Clear() {
	s.v6LastWarn = ""
	s.v6Problem.Store(nil)
}

// v6Issue — предупреждение для статуса: перехват IPv6 выбран в настройках, но
// правила не стоят. Без него причина видна только в журнале, а в интерфейсе
// режим выглядел бы работающим.
func (s *ServiceImpl) v6Issue(sr storage.SingboxRouterSettings) (Issue, bool) {
	tproxy := sr.RoutingMode == "" || sr.RoutingMode == "tproxy"
	if !sr.Enabled || !tproxy || !familyHasV6(sr.InterceptFamily) {
		return Issue{}, false
	}
	msg := s.v6Problem.Load()
	if msg == nil {
		return Issue{}, false
	}
	return Issue{Severity: "warning", Kind: "ipv6-intercept", Message: "Перехват IPv6: " + *msg}, true
}

// v6LayerActive — работает ли v6-слой при этих настройках: он есть только в
// режиме tproxy и только при семействе с IPv6.
func v6LayerActive(sr storage.SingboxRouterSettings) bool {
	tproxy := sr.RoutingMode == "" || sr.RoutingMode == "tproxy"
	return tproxy && familyHasV6(sr.InterceptFamily)
}

// checkV6SubnetsAccepted решает, можно ли сохранить next при сохранённых cur:
// IPv6-подсети в исключениях допустимы, только пока v6-слой работает — иначе
// правило под них поставить некому, и запись молча ничего не делала бы.
//
// Одно послабление: если слой не работал и раньше, а IPv6-часть списка не
// менялась, запись проходит. Так получается после смены режима (она идёт
// мимо PUT настроек и список не трогает): прочие правки настроек не должны
// упираться в старые записи. О таких записях говорит inertV6SubnetsIssue.
func checkV6SubnetsAccepted(next, cur storage.SingboxRouterSettings) error {
	if v6LayerActive(next) {
		return nil
	}
	want, err := resolveBypassSubnets6(next.BypassExtraSubnets)
	if err != nil || len(want) == 0 {
		// Нечитаемый список отвергает Normalize — своим текстом.
		return nil
	}
	if !v6LayerActive(cur) {
		if had, err := resolveBypassSubnets6(cur.BypassExtraSubnets); err == nil && slices.Equal(had, want) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrIPv6BypassInactive, strings.Join(want, ", "))
}

// inertV6SubnetsIssue — предупреждение для статуса: в исключениях остались
// IPv6-подсети, а v6-слой не работает (сменили режим). Они не действуют.
func inertV6SubnetsIssue(sr storage.SingboxRouterSettings) (Issue, bool) {
	if !sr.Enabled || v6LayerActive(sr) {
		return Issue{}, false
	}
	v6, err := resolveBypassSubnets6(sr.BypassExtraSubnets)
	if err != nil || len(v6) == 0 {
		return Issue{}, false
	}
	return Issue{
		Severity: "warning",
		Kind:     "ipv6-bypass-inert",
		Message: "В исключениях по подсетям есть IPv6-адреса (" + strings.Join(v6, ", ") +
			"), но перехват IPv6 не работает — они не действуют. Включите перехват IPv6 (режим TProxy) или удалите их.",
	}, true
}

// bypass6Issue — предупреждение для статуса: IPv6-половина geoip-обхода не
// собрана. Статус самого набора при этом сбоем не становится — IPv4-набор
// собран и действует (см. storeBypassSetOutcome).
func (s *ServiceImpl) bypass6Issue(sr storage.SingboxRouterSettings) (Issue, bool) {
	if !sr.Enabled || !v6LayerActive(sr) || len(sr.BypassGeoIPTags) == 0 {
		return Issue{}, false
	}
	msg := s.bypass6Problem.Load()
	if msg == nil {
		return Issue{}, false
	}
	return Issue{
		Severity: "warning",
		Kind:     "ipv6-bypass-set",
		Message:  "geoip-обход IPv6: набор не собран (" + *msg + "). IPv4-набор собран и действует.",
	}, true
}

// desiredV6 собирает желаемый спек v6-слоя из настроек и топологии роутера.
// Классов QoS в нём ещё нет: их проекцию вызывающий дописывает сам, после
// проверки xt_dscp (см. buildV6Spec).
func (s *ServiceImpl) desiredV6(ctx context.Context, sr storage.SingboxRouterSettings, mark string, policyMode bool) (V6Spec, v6WantState) {
	if !familyHasV6(sr.InterceptFamily) {
		return V6Spec{}, v6Off
	}
	s.reserveV6Ports()
	topo, err := collectV6Topology()
	if err != nil {
		s.v6Warn("не удалось прочитать адреса IPv6 роутера: " + err.Error())
		return V6Spec{}, v6Unknown
	}
	// Интерфейсы-источники — только в режиме политики, как в v4: при «все
	// устройства» джамп не привязан к интерфейсу, и туннели попадают в него
	// сами.
	var ingress []string
	if policyMode && len(sr.IngressInterfaces) > 0 {
		ingress = s.resolveIngressInterfaces(ctx, sr.IngressInterfaces)
	}
	spec, skipped, specErr := buildV6Spec(sr, mark, policyMode, topo, ingress, s.keenDNSBypass6())
	if list := strings.Join(skipped, ", "); list != s.v6SkippedLogged {
		s.v6SkippedLogged = list
		if list != "" {
			s.appLog.Warn("ipv6", "", "мосты без порта для перехвата IPv6 пропущены: "+list)
		}
	}
	// Настройки проходят валидацию на записи, так что сюда ошибка разбора
	// доходит только из правленного руками settings.json. Спек при этом
	// собран без нечитаемой части — перехват встаёт, но исключения из неё не
	// действуют, и молчать об этом нельзя.
	msg := ""
	if specErr != nil {
		msg = specErr.Error()
	}
	if msg != s.v6SpecErrLogged {
		s.v6SpecErrLogged = msg
		if msg != "" {
			s.appLog.Warn("ipv6", "", "исключения перехвата IPv6 разобраны не полностью: "+msg)
		}
	}
	return spec, v6On
}

// reserveV6ListenPorts — шов над резервом портов v6-слоя.
var reserveV6ListenPorts = ReserveV6ListenPorts

// reserveV6Ports убирает порты v6-слоя из эфемерного пула ядра — один раз за
// жизнь процесса и только когда перехват IPv6 включён. Отказ не мешает слою
// встать (как и резерв v4-портов на старте демона), но попадает в журнал.
// Попытка одна, без повтора на каждой сверке: sysctl либо пишется, либо нет.
func (s *ServiceImpl) reserveV6Ports() {
	if s.v6PortsReserved {
		return
	}
	s.v6PortsReserved = true
	if err := reserveV6ListenPorts(); err != nil {
		s.appLog.Warn("ipv6", "", "не удалось зарезервировать порты инбаундов IPv6: "+err.Error())
	}
}

// healV6Inbounds приводит инбаунды v6-слоя в применённом конфиге к спеку.
// Возвращает true, если конфиг переписан (sing-box перечитает его).
func (s *ServiceImpl) healV6Inbounds(ctx context.Context, sr storage.SingboxRouterSettings, want V6Spec, state v6WantState) (bool, error) {
	if state == v6Unknown {
		return false, nil
	}
	// Выключенный слой проверяем один раз за жизнь процесса: при "ipv4_only"
	// это горячий путь каждого тика, а появиться наши инбаунды в конфиге сами
	// не могут.
	if state == v6Off && s.v6OffSettled {
		return false, nil
	}
	cfg, err := s.loadAppliedRouterConfig()
	if err != nil {
		return false, err
	}
	inbounds, changed := ensureV6Inbounds(cfg.Inbounds, want, state == v6On, sr.UDPTimeout, sr.UDPNATMax)
	if changed {
		cfg.Inbounds = inbounds
		if err := s.persistConfigDirect(ctx, cfg); err != nil {
			return false, err
		}
	}
	s.v6OffSettled = state == v6Off
	return changed, nil
}

// waitForV6Sockets ждёт, пока sing-box привяжет инбаунды спека.
func (s *ServiceImpl) waitForV6Sockets(ctx context.Context, want V6Spec, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if v6SocketsProbe(want) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// syncV6 приводит v6-правила к желаемому состоянию. engineDown и force
// приходят от v4-пути: при мёртвом движке правила не ставятся (как и в v4,
// #221), force — первая сверка после старта демона. inboundsHealed — конфиг
// только что переписан, sing-box перечитывает его: даём сокетам время встать.
//
// Fail-closed устроен как в v4 (reconcileInstalled): движок мёртв, а джампы
// перехвата снесены — ставится блокировка AWGM6-BLACKHOLE с теми же
// исключениями и тем же селектором; движок вернулся и перехват на месте —
// блокировка снимается. При целых джампах и мёртвом движке ничего не
// трогается: перехват в мёртвый порт сам роняет трафик.
//
// Вызывается только под transitionMu (enable и reconcileInstalled).
func (s *ServiceImpl) syncV6(ctx context.Context, want V6Spec, state v6WantState, engineDown, force, inboundsHealed bool) {
	it := s.deps.IPTables
	if state == v6Unknown {
		return
	}
	// Безусловный снос сироты — один раз за процесс: force держится, пока
	// netfilterStateKnown=false, а при неготовом движке это каждый тик часами.
	sweep := force && !s.v6StartSwept
	if state == v6Off {
		s.teardownV6(ctx, "перехват IPv6 выключен в настройках — правила сняты", sweep)
		s.v6StartSwept = true
		s.v6Clear()
		return
	}
	if !v6HasJumps(want) {
		// IPv6 на LAN не поднят (или метки нет): ставить нечего.
		s.teardownV6(ctx, "на LAN-мостах пропал IPv6 — правила перехвата сняты", sweep)
		s.v6StartSwept = true
		s.v6Warn("перехват IPv6 включён, но ни на одном LAN-мосту нет IPv6 — правила не ставятся")
		return
	}
	st, err := it.probe6(ctx)
	if err != nil {
		// «Не знаю», а не «сломано» — тот же довод, что у probeAll. Блокировку
		// при этом не снимаем: транзиентный отказ во время перестройки
		// файрвола снёс бы DROP при живой утечке.
		s.v6Warn("состояние перехвата IPv6 не снято: " + err.Error())
		return
	}
	if engineDown {
		// Слой уже стоял (цепочки на месте), а джампы снесены — трафик
		// политики пошёл бы мимо sing-box. Блокируем его до возвращения движка.
		if st.anyChain && !st.jumps {
			s.engageBlackhole6(ctx, want, st)
		}
		// Перехват в непривязанные сокеты не ставим — как в v4.
		return
	}

	changed := !equalV6Spec(s.appliedV6, &want)
	if force || changed || !st.jumps {
		if inboundsHealed {
			s.waitForV6Sockets(ctx, want, v6ReloadWait)
		}
		if !v6SocketsProbe(want) {
			// Блокировка, если стоит, остаётся: перехвата ещё нет.
			s.v6Warn("инбаунды IPv6 ещё не слушают — установка правил отложена до следующей сверки")
			return
		}
		// Набор обязан существовать до правила `--match-set`: иначе
		// ip6tables-restore падает целиком. Пустой набор безопасен — он просто
		// ничего не исключает, наполнение придёт следом.
		if want.BypassGeoIPSet {
			if err := ensureBypassSet6(ctx); err != nil {
				s.v6Warn("geoip-обход IPv6: набор не создан (" + err.Error() + ") — правила не ставятся")
				return
			}
		}
		if err := it.Install6(ctx, want); err != nil {
			// Часть таблиц могла примениться — снимок неизвестен, следующая
			// сверка переустановит.
			s.appliedV6 = nil
			s.v6KernelUnknown = true
			s.v6Warn("не удалось поставить правила перехвата IPv6: " + err.Error())
			return
		}
		prev := s.appliedV6
		s.appliedV6 = &want
		s.v6KernelUnknown = false
		switch {
		case want.BypassGeoIPSet && (prev == nil || !prev.BypassGeoIPSet):
			// Набор только что появился в правилах и пуст — наполняем. Общий
			// проход пересоберёт оба набора; он асинхронный и сам склеивает
			// повторные запуски.
			s.TriggerBypassSetPopulate()
		case !want.BypassGeoIPSet:
			// Правила на набор больше не ссылаются — теперь его можно снести.
			if err := dropBypassSet6(ctx); err != nil {
				s.appLog.Warn("ipv6", "", "geoip-обход IPv6: снос набора: "+err.Error())
			}
		}
		switch {
		case prev == nil:
			s.appLog.Info("ipv6", "", fmt.Sprintf("перехват IPv6 установлен (мостов: %d, интерфейсов-источников: %d)",
				len(want.Bridges), len(want.IngressInterfaces)))
		case !st.jumps:
			s.appLog.Warn("ipv6", "", "правила перехвата IPv6 пропали из netfilter — переустановлены")
		default:
			s.appLog.Info("ipv6", "", "правила перехвата IPv6 обновлены (сменились адреса роутера или настройки)")
		}
	}
	s.v6Clear()

	// Движок жив, перехват на месте (устоявшееся состояние либо только что
	// переустановлен) — блокировку снимаем. ПОСЛЕ установки, чтобы между
	// снятием DROP и возвратом перехвата не было окна. Наблюдаем факт, а не
	// память: файл правил блокировки переживает рестарт демона, и его
	// возвращает DEAD-ветка хука.
	if s.appliedBlackhole6 != nil || st.blackhole || blackhole6FilePresent() {
		it.RemoveBlackhole6(ctx)
		s.appliedBlackhole6 = nil
		s.appLog.Info("ipv6", "", "движок восстановлен — fail-closed блокировка IPv6 снята")
	}
}

// engageBlackhole6 ставит или обновляет fail-closed блокировку IPv6. Спек
// блокировки — тот же спек перехвата: она дропает ровно то, что уехало бы в
// sing-box, с теми же исключениями. Переустановка — когда блокировки в
// netfilter нет (цепочка или её джамп) либо сменились исключения.
func (s *ServiceImpl) engageBlackhole6(ctx context.Context, want V6Spec, st v6State) {
	if st.blackhole && equalBlackholeSpec6(s.appliedBlackhole6, &want) {
		return
	}
	// Набор обязан существовать, иначе restore блокировки падает целиком и
	// fail-closed не встаёт вовсе; пустой набор безопасен.
	if want.BypassGeoIPSet {
		if err := ensureBypassSet6(ctx); err != nil {
			s.v6Warn("fail-closed блокировка IPv6: набор обхода не создан (" + err.Error() + ")")
			return
		}
	}
	first := s.appliedBlackhole6 == nil
	if err := s.deps.IPTables.InstallBlackhole6(ctx, want); err != nil {
		// Блокировка могла встать в ядре без файла правил (отказ записи после
		// restore) — снос обязан её найти.
		s.v6KernelUnknown = true
		s.appLog.Warn("ipv6", "", "не удалось поставить fail-closed блокировку IPv6: "+err.Error())
		return
	}
	s.appliedBlackhole6 = &want
	switch {
	case first:
		s.appLog.Warn("ipv6", "", "движок не работает, джампы перехвата IPv6 снесены — включена fail-closed блокировка (трафик политики по IPv6 дропается, не идёт мимо sing-box)")
	case !st.blackhole:
		s.appLog.Warn("ipv6", "", "fail-closed блокировка IPv6 пропала из netfilter — переустановлена")
	default:
		s.appLog.Info("ipv6", "", "исключения fail-closed блокировки IPv6 обновлены")
	}
}

// teardownV6 сносит v6-слой, если он есть. Наблюдает и снимки в памяти, и
// файлы правил: файлы переживают рестарт демона, и на одной памяти хук
// продолжал бы возвращать перехват или блокировку, выключенные в настройках.
// Без обращений к ip6tables, когда сносить нечего, — это горячий путь каждого
// тика при "ipv4_only".
//
// force (первая сверка после старта демона) сносит и без следов: сирота
// бывает и без файлов — демон умер посреди Uninstall6, который удаляет их
// первыми, или restore закоммитил часть таблиц, а v6KernelUnknown жил только в
// памяти. reason пишется в журнал, только если следы были: иначе каждый старт
// у всех с "ipv4_only" сообщал бы о сносе того, чего не было.
func (s *ServiceImpl) teardownV6(ctx context.Context, reason string, force bool) {
	traces := s.appliedV6 != nil || s.appliedBlackhole6 != nil || s.v6KernelUnknown || v6RulesFilePresent() || blackhole6FilePresent()
	if !traces && !force {
		return
	}
	// Uninstall6 снимает и блокировку.
	s.deps.IPTables.Uninstall6(ctx)
	s.appliedV6 = nil
	s.appliedBlackhole6 = nil
	s.v6KernelUnknown = false
	// Только после Uninstall6: пока правило `--match-set` в ядре, набор занят.
	if err := dropBypassSet6(ctx); err != nil {
		s.appLog.Warn("ipv6", "", "geoip-обход IPv6: снос набора: "+err.Error())
	}
	if traces && reason != "" {
		s.appLog.Info("ipv6", "", reason)
	}
}

// sweepV6 сносит v6-слой безусловно. Для путей, где режим tproxy не активен
// (fakeip-tun, policy-tun) и где v4-остатки прежнего режима снимает такой же
// безусловный Uninstall: слой живёт только в tproxy, но его цепочки, хук и
// файлы правил переживают и рестарт демона, и аварийную смену режима, а в
// чужом режиме их никто не сверяет. Снос с force: по одним снимкам в памяти и
// файлам правил сирота без файла (демон умер посреди Uninstall6) так и
// осталась бы заворачивать IPv6 в порт без слушателя.
//
// Вызывается под transitionMu, как и остальные правки состояния слоя.
func (s *ServiceImpl) sweepV6(ctx context.Context) {
	s.teardownV6(ctx, "", true)
	s.v6Clear()
}

// bypassSet6Wanted — нужен ли IPv6-набор обхода по текущим настройкам. Читает
// настройки заново: наполнение идёт асинхронно и минуты, семейство за это
// время могли переключить.
func (s *ServiceImpl) bypassSet6Wanted() (bool, error) {
	if s.deps.Settings == nil {
		return false, nil
	}
	st, err := s.deps.Settings.Get()
	if err != nil {
		return false, err
	}
	return familyHasV6(st.SingboxRouter.InterceptFamily), nil
}
