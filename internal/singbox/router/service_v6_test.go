package router

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hoaxisr/awg-manager/internal/logging"
	"github.com/hoaxisr/awg-manager/internal/singbox/router/bypassset"
	"github.com/hoaxisr/awg-manager/internal/storage"
)

// v6Env — подмены швов v6-слоя на время теста.
type v6Env struct {
	topo      v6Topology
	topoErr   error
	bound     bool
	rulesFile bool
	// blackholeFile — «файл правил блокировки лежит на диске».
	blackholeFile bool

	setEnsured   int
	setEnsureErr error
	setDropped   int

	// portsReserved — сколько раз слой просил зарезервировать свои порты.
	portsReserved   int
	portsReserveErr error
}

// Резерв портов пишет в sysctl ядра. Тесты нередко идут под root (контейнер,
// WSL), где запись прошла бы по-настоящему, — поэтому для всего тестового
// бинаря шов по умолчанию пуст; считают вызовы те тесты, которым это нужно
// (stubV6Env).
//
// То же для сноса набора AWGM-BYPASS6: слой сносится в каждом пути выхода из
// режима (sweepV6), и без этого любой такой тест звал бы ipset хоста.
func init() {
	reserveV6ListenPorts = func() error { return nil }
	dropBypassSet6 = func(context.Context) error { return nil }
}

// realDropBypassSet6 — боевая реализация, снятая до подмены в init: её
// проверяет TestDropBypassSet6_RemovesDump.
var realDropBypassSet6 = dropBypassSet6

func stubV6Env(t *testing.T) *v6Env {
	t.Helper()
	env := &v6Env{
		topo:  v6Topology{Bridges: []string{"br0"}, LocalCIDRs: []string{"2001:db8:1::/64"}},
		bound: true,
	}
	oldTopo, oldProbe, oldFile := collectV6Topology, v6SocketsProbe, v6RulesFilePresent
	oldEnsure, oldDrop := ensureBypassSet6, dropBypassSet6
	oldBH := blackhole6FilePresent
	oldReserve := reserveV6ListenPorts
	reserveV6ListenPorts = func() error { env.portsReserved++; return env.portsReserveErr }
	blackhole6FilePresent = func() bool { return env.blackholeFile }
	collectV6Topology = func() (v6Topology, error) { return env.topo, env.topoErr }
	v6SocketsProbe = func(V6Spec) bool { return env.bound }
	v6RulesFilePresent = func() bool { return env.rulesFile }
	// Набор AWGM-BYPASS6: настоящего ipset в тестах нет — считаем вызовы.
	ensureBypassSet6 = func(context.Context) error { env.setEnsured++; return env.setEnsureErr }
	dropBypassSet6 = func(context.Context) error { env.setDropped++; return nil }
	t.Cleanup(func() {
		collectV6Topology, v6SocketsProbe, v6RulesFilePresent = oldTopo, oldProbe, oldFile
		ensureBypassSet6, dropBypassSet6 = oldEnsure, oldDrop
		blackhole6FilePresent = oldBH
		reserveV6ListenPorts = oldReserve
	})
	return env
}

// newV6ReconcileService — служба reconcileInstalled с живым движком и
// подключённым v6-слоем.
func newV6ReconcileService(t *testing.T, family string) (*ServiceImpl, *v6Exec, *v6Env, storage.SingboxRouterSettings) {
	t.Helper()
	sb := newTestSingbox(t)
	sb.isRunningFn = func() (bool, int) { return true, 1234 }
	svc := newReconcileInstalledService(t, sb)
	fe := &v6Exec{}
	svc.deps.IPTables = newV6IPTables(fe)
	env := stubV6Env(t)
	sr := reconcileInstalledSettings
	sr.InterceptFamily = family
	return svc, fe, env, sr
}

func mustReconcile(t *testing.T, svc *ServiceImpl, sr storage.SingboxRouterSettings) {
	t.Helper()
	if err := svc.reconcileInstalled(context.Background(), sr); err != nil {
		t.Fatalf("reconcileInstalled: %v", err)
	}
}

// Семейство "both": v6-правила ставятся с меткой политики и мостом из
// топологии, а на устоявшемся состоянии следующий тик ничего не трогает.
func TestReconcileInstalled_V6Both_InstallsThenSteady(t *testing.T) {
	svc, fe, _, sr := newV6ReconcileService(t, FamilyBoth)

	mustReconcile(t, svc, sr)
	if len(fe.restores) != 1 {
		t.Fatalf("первый тик обязан поставить v6-правила: restores=%d, want 1", len(fe.restores))
	}
	for _, want := range []string{
		"-A PREROUTING -i br0 -m mark --mark 0xffffaaa -m conntrack --ctdir ORIGINAL -j " + Chain6Name,
		"-A " + Chain6Name + " -d 2001:db8:1::/64 -j RETURN",
	} {
		if !strings.Contains(fe.restores[0], want) {
			t.Errorf("в правилах нет %q:\n%s", want, fe.restores[0])
		}
	}
	if svc.appliedV6 == nil {
		t.Fatal("снимок применённого v6-спека не записан")
	}

	fe.dump = v6JumpsDump()
	mustReconcile(t, svc, sr)
	if len(fe.restores) != 1 {
		t.Errorf("устоявшееся состояние: повторной установки быть не должно, restores=%d", len(fe.restores))
	}
}

// Перестройка файрвола NDMS снесла v6-джампы при целых цепочках, а хук по
// какой-то причине не отработал — сверка обязана вернуть перехват.
func TestReconcileInstalled_V6JumpsWiped_Reinstalls(t *testing.T) {
	svc, fe, _, sr := newV6ReconcileService(t, FamilyBoth)
	fe.dump = v6JumpsDump()
	mustReconcile(t, svc, sr) // первая установка
	n := len(fe.restores)

	fe.dump = "-N " + Chain6Name + "\n-N " + Redirect6Chain + "\n"
	mustReconcile(t, svc, sr)
	if len(fe.restores) != n+1 {
		t.Errorf("снесённые джампы обязаны дать переустановку: restores=%d, want %d", len(fe.restores), n+1)
	}
}

// Провайдер сменил префикс LAN: исключения в правилах обязаны обновиться,
// иначе трафик к собственной сети уходил бы в sing-box.
func TestReconcileInstalled_V6FollowsPrefixChange(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	fe.dump = v6JumpsDump()
	mustReconcile(t, svc, sr)

	env.topo.LocalCIDRs = []string{"2001:db8:2::/64"}
	mustReconcile(t, svc, sr)
	last := fe.restores[len(fe.restores)-1]
	if !strings.Contains(last, "2001:db8:2::/64") || strings.Contains(last, "2001:db8:1::/64") {
		t.Errorf("исключения не обновились под новый префикс:\n%s", last)
	}
}

// Инбаунды ещё не слушают — правила в непривязанные сокеты ставить нельзя
// (#221): установка откладывается до следующей сверки.
func TestReconcileInstalled_V6SocketsNotBound_Defers(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	env.bound = false
	mustReconcile(t, svc, sr)
	if len(fe.restores) != 0 || svc.appliedV6 != nil {
		t.Fatalf("при непривязанных сокетах установки быть не должно: restores=%d", len(fe.restores))
	}
	env.bound = true
	mustReconcile(t, svc, sr)
	if len(fe.restores) != 1 {
		t.Errorf("после привязки сокетов правила обязаны встать: restores=%d, want 1", len(fe.restores))
	}
}

// Мёртвый движок: новую установку не делаем — как и в v4.
func TestReconcileInstalled_V6EngineDown_NoInstall(t *testing.T) {
	sb := newTestSingbox(t) // мёртв
	svc := newReconcileInstalledService(t, sb)
	fe := &v6Exec{}
	svc.deps.IPTables = newV6IPTables(fe)
	stubV6Env(t)
	sr := reconcileInstalledSettings
	sr.InterceptFamily = FamilyBoth

	mustReconcile(t, svc, sr)
	if len(fe.restores) != 0 {
		t.Errorf("при мёртвом движке v6-правила ставить нельзя: restores=%d", len(fe.restores))
	}
}

// Переключение на "ipv4_only" при установленном слое сносит его целиком.
func TestReconcileInstalled_V6SwitchedOff_Uninstalls(t *testing.T) {
	svc, fe, _, sr := newV6ReconcileService(t, FamilyBoth)
	fe.dump = v6JumpsDump()
	mustReconcile(t, svc, sr)
	if svc.appliedV6 == nil {
		t.Fatal("предусловие: слой обязан быть установлен")
	}

	sr.InterceptFamily = FamilyIPv4Only
	mustReconcile(t, svc, sr)
	if svc.appliedV6 != nil || fe.cleanups != 1 {
		t.Errorf("слой обязан быть снесён: appliedV6=%v, cleanups=%d", svc.appliedV6, fe.cleanups)
	}
	if !hasCall(fe.ip6t, "-t", "mangle", "-X", Chain6Name) {
		t.Errorf("цепочка не удалена: %v", fe.ip6t)
	}
}

// После рестарта демона снимка в памяти нет, а правила и хук на месте: слой,
// выключенный в настройках, обязан быть снесён по факту файла правил.
func TestReconcileInstalled_V6Off_StaleFileUninstalls(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyIPv4Only)
	env.rulesFile = true
	mustReconcile(t, svc, sr)
	if fe.cleanups != 1 {
		t.Errorf("оставшийся файл правил обязан привести к сносу: cleanups=%d", fe.cleanups)
	}
}

// "ipv4_only" без следов слоя — горячий путь каждого тика у всех, кому IPv6
// не нужен: ни одного обращения к ip6tables.
func TestReconcileInstalled_V6Off_NoIP6TablesCalls(t *testing.T) {
	svc, fe, _, sr := newV6ReconcileService(t, FamilyIPv4Only)
	calls := 0
	fe.onRunOutput = func() { calls++ }
	mustReconcile(t, svc, sr)
	mustReconcile(t, svc, sr)
	if calls != 0 || len(fe.ip6t) != 0 || len(fe.restores) != 0 || fe.cleanups != 0 {
		t.Errorf("выключенный слой не должен трогать ip6tables: out=%d, run=%d, restore=%d, cleanup=%d",
			calls, len(fe.ip6t), len(fe.restores), fe.cleanups)
	}
}

// Сирота без следов: демон умер посреди Uninstall6 (файлы правил он удаляет
// первыми) или restore закоммитил часть таблиц, а признак неизвестного
// состояния жил только в памяти. После рестарта ни снимков, ни файлов — первая
// сверка обязана снести слой безусловно, как sweepV6 в чужих режимах.
func TestReconcileInstalled_V6Off_FirstTickSweepsTracelessOrphan(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyIPv4Only)
	svc.netfilterStateKnown = false
	fe.dump = v6JumpsDump()
	mustReconcile(t, svc, sr)
	if fe.cleanups != 1 || env.setDropped != 1 || !hasCall(fe.ip6t, "-t", "mangle", "-X", Chain6Name) {
		t.Fatalf("тик 1: сирота обязана быть снесена: cleanups=%d dropped=%d calls=%v", fe.cleanups, env.setDropped, fe.ip6t)
	}

	n := len(fe.ip6t)
	mustReconcile(t, svc, sr)
	if len(fe.ip6t) != n || fe.cleanups != 1 {
		t.Errorf("тик 2: свип обязан быть разовым: calls %d → %d, cleanups=%d", n, len(fe.ip6t), fe.cleanups)
	}
}

// Пока движок не готов, netfilterStateKnown остаётся false и force приходит
// каждый тик — часами. Безусловный снос обязан быть разовым за процесс, иначе
// горячий путь "ipv4_only" гонял бы ip6tables, ip и ipset на каждом тике.
func TestReconcileInstalled_V6Off_EngineDownSweepsOnce(t *testing.T) {
	svc := newReconcileInstalledService(t, newTestSingbox(t)) // мёртв
	svc.netfilterStateKnown = false
	fe := &v6Exec{}
	svc.deps.IPTables = newV6IPTables(fe)
	env := stubV6Env(t)
	sr := reconcileInstalledSettings
	sr.InterceptFamily = FamilyIPv4Only

	mustReconcile(t, svc, sr)
	mustReconcile(t, svc, sr)
	mustReconcile(t, svc, sr)
	if fe.cleanups != 1 || env.setDropped != 1 {
		t.Errorf("снос обязан быть разовым: cleanups=%d dropped=%d", fe.cleanups, env.setDropped)
	}
}

// То же для ветки «перехват включён, но на LAN нет IPv6»: сирота прежней
// установки снимается на первой сверке и без следов.
func TestReconcileInstalled_V6NoBridges_FirstTickSweepsTracelessOrphan(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	svc.netfilterStateKnown = false
	env.topo = v6Topology{}
	fe.dump = v6JumpsDump()
	mustReconcile(t, svc, sr)
	if fe.cleanups != 1 || !hasCall(fe.ip6t, "-t", "mangle", "-X", Chain6Name) {
		t.Errorf("сирота обязана быть снесена: cleanups=%d calls=%v", fe.cleanups, fe.ip6t)
	}
}

// Снос без следов на старте — у всех с "ipv4_only" на каждом старте демона:
// сообщение «правила сняты» о том, чего не было, — ложь в журнале.
func TestReconcileInstalled_V6Off_TracelessSweepNotLogged(t *testing.T) {
	svc, _, _, sr := newV6ReconcileService(t, FamilyIPv4Only)
	svc.netfilterStateKnown = false
	rec := &recordingAppLogger{}
	svc.appLog = logging.NewScopedLogger(rec, logging.GroupRouting, logging.SubSingboxRouter)
	mustReconcile(t, svc, sr)
	for _, e := range rec.entries {
		if strings.Contains(e, "сняты") {
			t.Errorf("снос без следов не должен сообщать о снятии правил: %q", e)
		}
	}
}

// Топологию снять не удалось — это «не знаю», а не «IPv6 пропал»: рабочие
// правила трогать нельзя.
func TestReconcileInstalled_V6TopologyError_LeavesLayerAlone(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	fe.dump = v6JumpsDump()
	mustReconcile(t, svc, sr)
	n := len(fe.restores)

	env.topoErr = errors.New("read /proc/net/if_inet6: boom")
	mustReconcile(t, svc, sr)
	if svc.appliedV6 == nil || fe.cleanups != 0 || len(fe.restores) != n {
		t.Errorf("отказ чтения топологии не должен менять слой: applied=%v, cleanups=%d, restores=%d (было %d)",
			svc.appliedV6 != nil, fe.cleanups, len(fe.restores), n)
	}
}

// IPv6 на LAN пропал (мостов с link-local нет): правила сносятся.
func TestReconcileInstalled_V6NoBridges_Uninstalls(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	fe.dump = v6JumpsDump()
	mustReconcile(t, svc, sr)

	env.topo = v6Topology{}
	mustReconcile(t, svc, sr)
	if svc.appliedV6 != nil || fe.cleanups != 1 {
		t.Errorf("без мостов слой обязан быть снесён: applied=%v, cleanups=%d", svc.appliedV6 != nil, fe.cleanups)
	}
}

// Отказ установки v6 не роняет сверку: IPv4-перехват важнее.
func TestReconcileInstalled_V6InstallError_DoesNotFailReconcile(t *testing.T) {
	svc, fe, _, sr := newV6ReconcileService(t, FamilyBoth)
	fe.restoreErr = errors.New("ip6tables-restore: line 4 failed")
	mustReconcile(t, svc, sr)
	if svc.appliedV6 != nil {
		t.Error("после провала установки снимок обязан остаться пустым — следующая сверка повторит")
	}
}

// ipv6_only: IPv4 не перехватывается, поэтому fail-closed блокировку при
// мёртвом движке и снесённых джампах ставить нельзя — она уронила бы трафик,
// который должен идти мимо sing-box.
func TestReconcileInstalled_V4Off_NoBlackhole(t *testing.T) {
	sb := newTestSingbox(t) // мёртв
	svc := newReconcileInstalledService(t, sb)
	var restores []string
	ipt := newStubIPTables(func(_ context.Context, in string) error { restores = append(restores, in); return nil })
	ipt.runIPTablesOut = func(context.Context, ...string) (string, error) { return chainsOnlyDump(), nil }
	svc.deps.IPTables = ipt
	sr := reconcileInstalledSettings
	sr.InterceptFamily = FamilyIPv6Only

	mustReconcile(t, svc, sr)
	for _, r := range restores {
		if strings.Contains(r, BlackholeChain) {
			t.Fatalf("в режиме ipv6_only блокировка ставиться не должна:\n%s", r)
		}
	}
	if svc.appliedBlackhole != nil {
		t.Error("снимок блокировки обязан остаться пустым")
	}
}

func TestNormalize_InterceptFamily(t *testing.T) {
	base := storage.SingboxRouterSettings{WANAutoDetect: true}

	got, err := NormalizeSingboxRouterSettings(base)
	if err != nil || got.InterceptFamily != FamilyIPv4Only {
		t.Errorf("пустое значение обязано нормализоваться в %q: %q, %v", FamilyIPv4Only, got.InterceptFamily, err)
	}
	for _, f := range []string{FamilyIPv4Only, FamilyBoth, FamilyIPv6Only} {
		base.InterceptFamily = f
		if got, err := NormalizeSingboxRouterSettings(base); err != nil || got.InterceptFamily != f {
			t.Errorf("%q: %q, %v", f, got.InterceptFamily, err)
		}
	}
	base.InterceptFamily = "ipv6"
	if _, err := NormalizeSingboxRouterSettings(base); err == nil || !strings.Contains(err.Error(), "interceptFamily") {
		t.Errorf("неизвестное значение обязано быть отвергнуто с именем поля: %v", err)
	}
}

func TestFamilyHelpers(t *testing.T) {
	cases := []struct {
		family string
		v4, v6 bool
	}{
		{"", true, false},
		{FamilyIPv4Only, true, false},
		{FamilyBoth, true, true},
		{FamilyIPv6Only, false, true},
	}
	for _, c := range cases {
		if familyHasV4(c.family) != c.v4 || familyHasV6(c.family) != c.v6 {
			t.Errorf("%q: v4=%v v6=%v, want %v %v", c.family, familyHasV4(c.family), familyHasV6(c.family), c.v4, c.v6)
		}
	}
}

// Перехват IPv6 без пакета ip6tables — отказ сохранения с понятной причиной,
// а не настройка, которая «включена, но не работает».
func TestUpdateSettings_V6WithoutIP6Tables_Rejected(t *testing.T) {
	old := ip6tablesAvailable
	ip6tablesAvailable = func() bool { return false }
	t.Cleanup(func() { ip6tablesAvailable = old })

	settingsStore := newTestSettingsStore(t, storage.SingboxRouterSettings{PolicyName: "Policy0"})
	svc := newTestService(t, Deps{
		Settings: settingsStore,
		IPTables: newStubIPTables(func(context.Context, string) error { return nil }),
	})

	err := svc.UpdateSettings(context.Background(), storage.SingboxRouterSettings{
		PolicyName:      "Policy0",
		WANAutoDetect:   true,
		InterceptFamily: FamilyBoth,
	})
	if !errors.Is(err, ErrIP6TablesMissing) {
		t.Fatalf("err = %v, want ErrIP6TablesMissing", err)
	}
	all, err := settingsStore.Load()
	if err != nil {
		t.Fatalf("settingsStore.Load: %v", err)
	}
	if familyHasV6(all.SingboxRouter.InterceptFamily) {
		t.Errorf("отвергнутое значение сохранено: %q", all.SingboxRouter.InterceptFamily)
	}
}

// Отказ — только на переходе к IPv6. Если перехват IPv6 уже включён, а пакет
// ip6tables потом удалили, остальные настройки должны сохраняться: иначе
// пользователь не смог бы поправить ничего, пока не вернёт пакет.
func TestUpdateSettings_V6AlreadyOn_OtherEditsPass(t *testing.T) {
	old := ip6tablesAvailable
	ip6tablesAvailable = func() bool { return false }
	t.Cleanup(func() { ip6tablesAvailable = old })

	// Тот же стенд, что у тестов UpdateSettings классов QoS: роутер выключен,
	// в netfilter ничего нет — сохранение проходит до конца.
	svc := newQoSLifecycleService(t, storage.SingboxRouterSettings{
		WANAutoDetect:   true,
		InterceptFamily: FamilyBoth,
	})

	err := svc.UpdateSettings(context.Background(), storage.SingboxRouterSettings{
		WANAutoDetect:   true,
		InterceptFamily: FamilyBoth,
		UDPTimeout:      "10m0s",
	})
	if err != nil {
		t.Fatalf("правка при уже включённом IPv6 не должна упираться в отсутствие ip6tables: %v", err)
	}
	all, err := svc.deps.Settings.Load()
	if err != nil {
		t.Fatalf("Settings.Load: %v", err)
	}
	if all.SingboxRouter.UDPTimeout != "10m0s" || all.SingboxRouter.InterceptFamily != FamilyBoth {
		t.Errorf("настройки не сохранены: udpTimeout=%q family=%q",
			all.SingboxRouter.UDPTimeout, all.SingboxRouter.InterceptFamily)
	}
}

// Geoip-обход: набор AWGM-BYPASS6 обязан существовать ДО ip6tables-restore —
// правило `--match-set` на отсутствующий набор роняет установку целиком.
func TestReconcileInstalled_V6GeoIPSet_EnsuredBeforeInstall(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	sr.BypassGeoIPTags = []string{"geoip:cn"}
	ensuredAtRestore := -1
	fe.onRestore = func(in string) error {
		ensuredAtRestore = env.setEnsured
		fe.restores = append(fe.restores, in)
		return nil
	}

	mustReconcile(t, svc, sr)
	if ensuredAtRestore != 1 {
		t.Fatalf("набор обязан быть создан до restore: ensured=%d на момент restore", ensuredAtRestore)
	}
	if len(fe.restores) != 1 || !strings.Contains(fe.restores[0], "--match-set AWGM-BYPASS6 dst -j RETURN") {
		t.Fatalf("в правилах нет обхода по набору:\n%v", fe.restores)
	}
}

// Набор создать не удалось (нет ipset, нет xt_set) — правила с `--match-set`
// ставить нельзя: restore упал бы. Установка откладывается, IPv4 не страдает.
func TestReconcileInstalled_V6GeoIPSet_EnsureFails_NoInstall(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	sr.BypassGeoIPTags = []string{"geoip:cn"}
	env.setEnsureErr = errors.New("ipset недоступен")

	mustReconcile(t, svc, sr)
	if len(fe.restores) != 0 || svc.appliedV6 != nil {
		t.Errorf("без набора правила ставить нельзя: restores=%d", len(fe.restores))
	}
}

// Теги сняты: набор сносится ПОСЛЕ переустановки правил без `--match-set` —
// раньше ядро ответило бы «set is in use».
func TestReconcileInstalled_V6GeoIPSet_DroppedAfterRulesReinstalled(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	sr.BypassGeoIPTags = []string{"geoip:cn"}
	fe.dump = v6JumpsDump()
	mustReconcile(t, svc, sr)
	if env.setDropped != 0 {
		t.Fatalf("пока теги выбраны, набор сносить нельзя: dropped=%d", env.setDropped)
	}

	droppedAtRestore := -1
	fe.onRestore = func(in string) error {
		droppedAtRestore = env.setDropped
		fe.restores = append(fe.restores, in)
		return nil
	}
	sr.BypassGeoIPTags = nil
	mustReconcile(t, svc, sr)
	if droppedAtRestore != 0 || env.setDropped != 1 {
		t.Errorf("набор обязан быть снесён после restore: на момент restore dropped=%d, итог %d", droppedAtRestore, env.setDropped)
	}
	if strings.Contains(fe.restores[len(fe.restores)-1], "--match-set") {
		t.Error("после снятия тегов правила на набор ссылаться не должны")
	}
}

// Снос слоя сносит и набор — после правил.
func TestReconcileInstalled_V6Off_DropsSet(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	sr.BypassGeoIPTags = []string{"geoip:cn"}
	fe.dump = v6JumpsDump()
	mustReconcile(t, svc, sr)

	sr.InterceptFamily = FamilyIPv4Only
	mustReconcile(t, svc, sr)
	if env.setDropped != 1 || fe.cleanups != 1 {
		t.Errorf("выключение перехвата IPv6 обязано снести правила и набор: dropped=%d cleanups=%d", env.setDropped, fe.cleanups)
	}
}

// Интерфейсы-источники — только в режиме политики, у каждого свой джамп. В
// режиме «все устройства» джамп один и к интерфейсу не привязан, как в v4:
// туннели попадают в перехват сами, отдельных правил под них нет.
func TestReconcileInstalled_V6IngressInterfaces(t *testing.T) {
	cases := map[string][]string{
		"policy": {
			"-A PREROUTING -i nwg3 -m conntrack --ctdir ORIGINAL -j " + Chain6Name,
			"-A PREROUTING -i nwg3 -j " + Redirect6Chain,
		},
		"all": {
			"-A PREROUTING -m conntrack --ctdir ORIGINAL -j " + Chain6Name,
			"-A PREROUTING -j " + Redirect6Chain,
			"-A " + Chain6Name + " -p udp -j TPROXY --on-port 51274",
		},
	}
	for mode, wants := range cases {
		svc, fe, _, sr := newV6ReconcileService(t, FamilyBoth)
		stubIngressLinks(t, "nwg3")
		sr.DeviceMode = mode
		sr.IngressInterfaces = []string{"iface:nwg3"}

		mustReconcile(t, svc, sr)
		if len(fe.restores) == 0 {
			t.Fatalf("%s: правила не поставлены", mode)
		}
		got := fe.restores[len(fe.restores)-1]
		for _, want := range wants {
			if !strings.Contains(got, want) {
				t.Errorf("%s: нет %q:\n%s", mode, want, got)
			}
		}
		if mode == "all" && strings.Contains(got, "-i nwg3") {
			t.Errorf("all: отдельных правил под источник быть не должно:\n%s", got)
		}
	}
}

// Классы QoS доезжают до правил ip6tables с портами IPv6-пары.
func TestReconcileInstalled_V6QoSClasses(t *testing.T) {
	oldStack := ipv6StackPresent
	ipv6StackPresent = func() bool { return true }
	t.Cleanup(func() { ipv6StackPresent = oldStack })
	stubXtDscpProbe(t, true, true)

	svc, fe, _, sr := newV6ReconcileService(t, FamilyBoth)
	sr.QoSClasses = []storage.SingboxQoSClass{{DSCP: 46, Outbound: "vpn", Enabled: true, Slot: 2}}

	mustReconcile(t, svc, sr)
	if len(fe.restores) == 0 {
		t.Fatal("правила не поставлены")
	}
	got := fe.restores[len(fe.restores)-1]
	for _, want := range []string{
		"-p udp -m dscp --dscp 46 -j TPROXY --on-port 51343",
		"-p tcp -m dscp --dscp 46 -j REDIRECT --to-ports 51363",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("нет %q:\n%s", want, got)
		}
	}
}

// Fail-closed как в v4: движок мёртв, слой стоял (цепочки на месте), а джампы
// перехвата снесены — ставится блокировка с DROP и тем же селектором, а
// перехват в мёртвый порт НЕ восстанавливается. Движок вернулся — перехват
// переустановлен, блокировка снята, причём после него.
func TestReconcileInstalled_V6Blackhole_EngagedThenLifted(t *testing.T) {
	sb := newTestSingbox(t) // мёртв
	svc := newReconcileInstalledService(t, sb)
	chainsOnly := "-N " + Chain6Name + "\n-N " + Redirect6Chain + "\n"
	fe := &v6Exec{dump: chainsOnly}
	svc.deps.IPTables = newV6IPTables(fe)
	env := stubV6Env(t)
	sr := reconcileInstalledSettings
	sr.InterceptFamily = FamilyBoth

	mustReconcile(t, svc, sr)
	if len(fe.restores) != 1 {
		t.Fatalf("ожидалась ровно одна установка — блокировка: restores=%d", len(fe.restores))
	}
	bh := fe.restores[0]
	for _, want := range []string{
		":" + Blackhole6Chain + " - [0:0]",
		"-A " + Blackhole6Chain + " -d fe80::/10 -j RETURN",
		"-A " + Blackhole6Chain + " -j DROP",
		"-A PREROUTING -i br0 -m mark --mark 0xffffaaa -m conntrack --ctdir ORIGINAL -j " + Blackhole6Chain,
	} {
		if !strings.Contains(bh, want) {
			t.Errorf("в блокировке нет %q:\n%s", want, bh)
		}
	}
	if strings.Contains(bh, "TPROXY") || strings.Contains(bh, "REDIRECT") {
		t.Errorf("при мёртвом движке перехват восстанавливаться не должен:\n%s", bh)
	}
	if svc.appliedBlackhole6 == nil || fe.blackholeWrites != 1 {
		t.Fatalf("снимок и файл блокировки обязаны появиться: applied=%v writes=%d", svc.appliedBlackhole6 != nil, fe.blackholeWrites)
	}

	// Блокировка на месте, спек не менялся — следующая сверка её не трогает.
	blackholeLive := chainsOnly + "-N " + Blackhole6Chain + "\n" +
		"-A PREROUTING -i br0 -m mark --mark 0xffffaaa -m conntrack --ctdir ORIGINAL -j " + Blackhole6Chain + "\n"
	fe.dump = blackholeLive
	mustReconcile(t, svc, sr)
	if len(fe.restores) != 1 {
		t.Errorf("живая блокировка с тем же спеком переустанавливаться не должна: restores=%d", len(fe.restores))
	}

	// Сменился префикс LAN — исключения блокировки обязаны обновиться.
	env.topo.LocalCIDRs = []string{"2001:db8:2::/64"}
	mustReconcile(t, svc, sr)
	if len(fe.restores) != 2 || !strings.Contains(fe.restores[1], "2001:db8:2::/64") {
		t.Fatalf("смена адресов обязана обновить блокировку: restores=%d", len(fe.restores))
	}

	// Движок вернулся: перехват ставится, блокировка снимается — после него.
	sb.isRunningFn = func() (bool, int) { return true, 4321 }
	cleanupsAtInstall := -1
	fe.onRestore = func(in string) error {
		cleanupsAtInstall = fe.blackholeCleanups
		fe.restores = append(fe.restores, in)
		return nil
	}
	mustReconcile(t, svc, sr)
	last := fe.restores[len(fe.restores)-1]
	if !strings.Contains(last, "-j TPROXY") {
		t.Fatalf("после возвращения движка обязан встать перехват:\n%s", last)
	}
	if cleanupsAtInstall != 0 || fe.blackholeCleanups == 0 || svc.appliedBlackhole6 != nil {
		t.Errorf("блокировка обязана быть снята ПОСЛЕ установки перехвата: на момент установки cleanups=%d, итог %d, applied=%v",
			cleanupsAtInstall, fe.blackholeCleanups, svc.appliedBlackhole6 != nil)
	}
	if !hasCall(fe.ip6t, "-t", "mangle", "-X", Blackhole6Chain) {
		t.Errorf("цепочка блокировки не удалена: %v", fe.ip6t)
	}
}

// Блокировка переживает рестарт демона файлом правил (её возвращает
// DEAD-ветка хука), а снимка в памяти у нового процесса нет: при живом движке
// она обязана быть снята по факту файла — иначе DROP остался бы навсегда.
func TestReconcileInstalled_V6Blackhole_StaleFileLifted(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	fe.dump = v6JumpsDump()
	env.blackholeFile = true

	mustReconcile(t, svc, sr)
	if fe.blackholeCleanups != 1 {
		t.Errorf("оставшийся файл блокировки при живом движке обязан привести к её снятию: cleanups=%d", fe.blackholeCleanups)
	}
}

// Движок мёртв, но джампы перехвата целы — ничего не трогаем: перехват в
// мёртвый порт сам роняет трафик, блокировка не нужна (как в v4).
func TestReconcileInstalled_V6EngineDown_JumpsIntact_NoBlackhole(t *testing.T) {
	sb := newTestSingbox(t) // мёртв
	svc := newReconcileInstalledService(t, sb)
	fe := &v6Exec{dump: v6JumpsDump()}
	svc.deps.IPTables = newV6IPTables(fe)
	stubV6Env(t)
	sr := reconcileInstalledSettings
	sr.InterceptFamily = FamilyBoth

	mustReconcile(t, svc, sr)
	if len(fe.restores) != 0 || svc.appliedBlackhole6 != nil {
		t.Errorf("при целых джампах блокировка не ставится: restores=%d", len(fe.restores))
	}
}

// Статус: перехват IPv6 выбран, но правила не встали — причина видна в
// интерфейсе, а не только в журнале; после успешной установки она уходит.
func TestV6Issue_ReportsWhyLayerIsDown(t *testing.T) {
	svc, _, env, sr := newV6ReconcileService(t, FamilyBoth)
	env.bound = false
	mustReconcile(t, svc, sr)

	issue, ok := svc.v6Issue(sr)
	if !ok || issue.Kind != "ipv6-intercept" || !strings.Contains(issue.Message, "инбаунды IPv6") {
		t.Fatalf("ожидалось предупреждение о непривязанных инбаундах: %+v, %v", issue, ok)
	}
	// Выбран только IPv4 — предупреждение о IPv6 неуместно, даже если оно
	// осталось от прошлой сверки.
	off := sr
	off.InterceptFamily = FamilyIPv4Only
	if _, ok := svc.v6Issue(off); ok {
		t.Error("при ipv4_only предупреждения о IPv6 быть не должно")
	}

	env.bound = true
	mustReconcile(t, svc, sr)
	if _, ok := svc.v6Issue(sr); ok {
		t.Error("после успешной установки предупреждение обязано уйти")
	}
}

// Мост без порта (имя не brN) не мешает слою встать, и писать о нём в журнал
// каждым тиком нельзя: успешная установка сбрасывает общее предупреждение, а
// пропуск моста — состояние на часы.
func TestReconcileInstalled_V6SkippedBridge_LoggedOnce(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	env.topo.Bridges = []string{"br0", "br99"}
	fe.dump = v6JumpsDump()

	mustReconcile(t, svc, sr)
	first := svc.v6SkippedLogged
	mustReconcile(t, svc, sr)
	if first != "br99" || svc.v6SkippedLogged != "br99" {
		t.Errorf("пропущенный мост обязан быть запомнен: %q → %q", first, svc.v6SkippedLogged)
	}
	if _, ok := svc.v6Issue(sr); ok {
		t.Error("пропуск моста — не причина считать перехват IPv6 неработающим")
	}
	if svc.appliedV6 == nil || len(svc.appliedV6.Bridges) != 1 {
		t.Errorf("слой обязан встать на оставшемся мосту: %+v", svc.appliedV6)
	}
}

// Порты v6-слоя убираются из эфемерного пула только при включённом перехвате
// IPv6 и один раз за жизнь процесса: при "ipv4_only" слой не оставляет на
// роутере ничего, включая запись в ip_local_reserved_ports.
func TestReconcileInstalled_V6PortsReservedOnlyWhenOn(t *testing.T) {
	svc, _, env, sr := newV6ReconcileService(t, FamilyIPv4Only)
	mustReconcile(t, svc, sr)
	mustReconcile(t, svc, sr)
	if env.portsReserved != 0 {
		t.Fatalf("при ipv4_only порты v6 резервировать нельзя: вызовов %d", env.portsReserved)
	}

	sr.InterceptFamily = FamilyBoth
	mustReconcile(t, svc, sr)
	mustReconcile(t, svc, sr)
	if env.portsReserved != 1 {
		t.Errorf("включение перехвата IPv6 обязано зарезервировать порты ровно один раз: вызовов %d", env.portsReserved)
	}
}

// Отказ резерва не мешает слою встать и не повторяется на каждой сверке.
func TestReconcileInstalled_V6PortsReserveFailure_NotFatal(t *testing.T) {
	svc, fe, env, sr := newV6ReconcileService(t, FamilyBoth)
	env.portsReserveErr = errors.New("read-only file system")
	mustReconcile(t, svc, sr)
	mustReconcile(t, svc, sr)
	if env.portsReserved != 1 {
		t.Errorf("попытка резерва обязана быть одна: вызовов %d", env.portsReserved)
	}
	if len(fe.restores) == 0 || svc.appliedV6 == nil {
		t.Errorf("отказ резерва портов не должен мешать установке правил")
	}
}

// sweepV6 — безусловный снос для путей вне режима tproxy: после рестарта
// демона снимков в памяти нет, файла правил может не быть, а цепочки и хук
// живы. Снос обязан пройти и в этом случае — и забрать набор AWGM-BYPASS6.
func TestSweepV6_UnconditionalEvenWithoutTraces(t *testing.T) {
	svc, fe, env, _ := newV6ReconcileService(t, FamilyIPv4Only)
	fe.dump = v6JumpsDump()
	// Ни снимков, ни файлов: teardownV6 здесь ничего бы не сделал.
	svc.sweepV6(context.Background())

	if fe.cleanups != 1 || fe.blackholeCleanups != 1 {
		t.Errorf("файлы правил, хук и блокировка обязаны быть сняты: cleanups=%d blackhole=%d", fe.cleanups, fe.blackholeCleanups)
	}
	if !hasCall(fe.ip6t, "-t", "mangle", "-X", Chain6Name) || !hasCall(fe.ip6t, "-t", "nat", "-X", Redirect6Chain) {
		t.Errorf("цепочки перехвата не удалены: %v", fe.ip6t)
	}
	if env.setDropped != 1 {
		t.Errorf("набор AWGM-BYPASS6 обязан быть снесён: dropped=%d", env.setDropped)
	}
}

// fakeip-tun: первый тик сверки сносит v6-слой прежнего tproxy-режима рядом с
// v4-остатками — в этом режиме его цепочки не сверяет никто. Свип разовый.
func TestReconcileFakeIPTun_FirstTickSweepsV6Layer(t *testing.T) {
	h := newFakeIPEnableHarness(t, "")
	if err := h.svc.enable(context.Background()); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	h.svc.deps.OpkgTunIndices = &recIndices{live: map[int]bool{0: true}}

	env := stubV6Env(t)
	fe := &v6Exec{dump: v6JumpsDump()}
	h.svc.deps.IPTables = newV6IPTables(fe)
	h.svc.netfilterStateKnown = false

	all, _ := h.store.Load()
	sr, _ := NormalizeSingboxRouterSettings(all.SingboxRouter)
	if err := h.svc.reconcileFakeIPTun(context.Background(), sr); err != nil {
		t.Fatalf("тик 1: %v", err)
	}
	if fe.cleanups != 1 || env.setDropped != 1 {
		t.Fatalf("тик 1: v6-слой обязан быть снесён: cleanups=%d dropped=%d", fe.cleanups, env.setDropped)
	}
	if !hasCall(fe.ip6t, "-t", "mangle", "-X", Chain6Name) {
		t.Errorf("тик 1: цепочка перехвата IPv6 не удалена: %v", fe.ip6t)
	}
	if err := h.svc.reconcileFakeIPTun(context.Background(), sr); err != nil {
		t.Fatalf("тик 2: %v", err)
	}
	if fe.cleanups != 1 {
		t.Errorf("тик 2: свип обязан быть разовым, cleanups=%d", fe.cleanups)
	}
}

// policy-tun: то же на выходе из режима — рядом с v4-Uninstall.
func TestPolicyTunDisable_SweepsV6Layer(t *testing.T) {
	h := newPolicyTunEnableHarness(t, "")
	stubOrphanNetdev(t, true)
	provisionPolicyTunForDisable(t, h)

	env := stubV6Env(t)
	fe := &v6Exec{dump: v6JumpsDump()}
	h.svc.deps.IPTables = newV6IPTables(fe)

	if err := h.svc.disable(context.Background()); err != nil {
		t.Fatalf("Disable(policy-tun): %v", err)
	}
	if fe.cleanups != 1 || env.setDropped != 1 {
		t.Errorf("v6-слой обязан быть снесён: cleanups=%d dropped=%d", fe.cleanups, env.setDropped)
	}
	if !hasCall(fe.ip6t, "-t", "mangle", "-X", Chain6Name) {
		t.Errorf("цепочка перехвата IPv6 не удалена: %v", fe.ip6t)
	}
}

// policy-tun с активными классами QoS: ветка сноса v4-правил не достигается,
// но первая сверка после рестарта демона обязана снять v6-сироту.
func TestReconcilePolicyTun_FirstTickSweepsV6Layer(t *testing.T) {
	h := newPolicyTunEnableHarness(t, "")
	all, _ := h.store.Load()
	all.SingboxRouter.QoSClasses = []storage.SingboxQoSClass{
		{DSCP: 46, Name: "VoIP", Outbound: "direct", Enabled: true},
	}
	if err := h.store.Update(func(cur *storage.Settings) error { *cur = *all; return nil }); err != nil {
		t.Fatalf("Save: %v", err)
	}
	h.svc.deps.IPTables = newStubIPTables(func(context.Context, string) error { return nil })
	h.svc.deps.WANIPCollector = &fakeWANIPCollector{}
	h.svc.deps.NetfilterPreflight = func(context.Context) error { return nil }
	h.svc.deps.XtDscpProbe = func(context.Context) bool { return true }
	provisionPolicyTunForReconcile(t, h)
	h.svc.deps.RunningConfig = &fakeRunningConfig{lines: healthyPolicyTunRC("OpkgTun0")}

	env := stubV6Env(t)
	fe := &v6Exec{dump: v6JumpsDump()}
	h.svc.deps.IPTables = newV6IPTables(fe)
	// Свежий процесс: про установленное состояние ничего не известно.
	h.svc.netfilterStateKnown = false

	all, _ = h.store.Load()
	sr, _ := NormalizeSingboxRouterSettings(all.SingboxRouter)
	if err := h.svc.reconcilePolicyTun(context.Background(), sr); err != nil {
		t.Fatalf("тик 1: %v", err)
	}
	if fe.cleanups != 1 || env.setDropped != 1 {
		t.Fatalf("тик 1: v6-слой обязан быть снесён: cleanups=%d dropped=%d", fe.cleanups, env.setDropped)
	}
	if err := h.svc.reconcilePolicyTun(context.Background(), sr); err != nil {
		t.Fatalf("тик 2: %v", err)
	}
	if fe.cleanups != 1 {
		t.Errorf("тик 2: свип обязан быть разовым, cleanups=%d", fe.cleanups)
	}
}

// buildV6Spec не глотает ошибки разбора исключений: спек собран без
// нечитаемой части, а причина возвращена вызывающему.
func TestBuildV6Spec_ReturnsResolverErrors(t *testing.T) {
	topo := v6Topology{Bridges: []string{"br0"}}

	spec, _, err := buildV6Spec(storage.SingboxRouterSettings{BypassExtraSubnets: "2001:db8::/48, мусор"}, "0xffffaab", true, topo, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "подсети") {
		t.Fatalf("нечитаемые подсети обязаны дать ошибку с пометкой «подсети», got %v", err)
	}
	if len(spec.Bridges) != 1 || len(spec.BypassCIDRs) != 0 {
		t.Errorf("спек обязан собраться без нечитаемой части: bridges=%v cidrs=%v", spec.Bridges, spec.BypassCIDRs)
	}

	_, _, err = buildV6Spec(storage.SingboxRouterSettings{BypassExtraPorts: "не порт"}, "0xffffaab", true, topo, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "порты") {
		t.Fatalf("нечитаемые порты обязаны дать ошибку с пометкой «порты», got %v", err)
	}

	if _, _, err := buildV6Spec(storage.SingboxRouterSettings{BypassExtraSubnets: "2001:db8::/48", BypassExtraPorts: "443 TCP"}, "0xffffaab", true, topo, nil, nil); err != nil {
		t.Errorf("читаемые исключения ошибки не дают: %v", err)
	}
}

// Ошибка разбора исключений доходит до журнала — один раз, а не каждые 30
// секунд сверки, — и спек при этом собран. Настройки проходят валидацию на
// записи и в начале сверки, так что сюда она доходит только мимо них; зовём
// desiredV6 напрямую.
func TestDesiredV6_SpecError_LoggedOnce(t *testing.T) {
	svc, _, _, sr := newV6ReconcileService(t, FamilyBoth)
	sr.BypassExtraSubnets = "2001:db8::/48, мусор"

	spec, state := svc.desiredV6(context.Background(), sr, "0xffffaab", true)
	if state != v6On || len(spec.Bridges) != 1 {
		t.Fatalf("нечитаемые исключения не должны мешать спеку собраться: state=%v bridges=%v", state, spec.Bridges)
	}
	first := svc.v6SpecErrLogged
	if !strings.Contains(first, "подсети") {
		t.Fatalf("ошибка разбора исключений обязана быть замечена, got %q", first)
	}
	svc.desiredV6(context.Background(), sr, "0xffffaab", true)
	if svc.v6SpecErrLogged != first {
		t.Errorf("та же ошибка не должна перезаписываться: %q → %q", first, svc.v6SpecErrLogged)
	}

	sr.BypassExtraSubnets = "2001:db8::/48"
	svc.desiredV6(context.Background(), sr, "0xffffaab", true)
	if svc.v6SpecErrLogged != "" {
		t.Errorf("исправленный список обязан снять запомненную ошибку: %q", svc.v6SpecErrLogged)
	}
}

// IPv6-подсети в исключениях принимаются, только пока v6-слой работает.
func TestCheckV6SubnetsAccepted(t *testing.T) {
	tproxy := func(family, subnets string) storage.SingboxRouterSettings {
		return storage.SingboxRouterSettings{RoutingMode: "tproxy", InterceptFamily: family, BypassExtraSubnets: subnets}
	}
	mode := func(mode, family, subnets string) storage.SingboxRouterSettings {
		return storage.SingboxRouterSettings{RoutingMode: mode, InterceptFamily: family, BypassExtraSubnets: subnets}
	}
	const v6 = "10.0.0.0/8, 2001:db8::/48"
	cases := []struct {
		name      string
		next, cur storage.SingboxRouterSettings
		reject    bool
	}{
		{"слой работает — принимаем", tproxy(FamilyBoth, v6), tproxy(FamilyBoth, ""), false},
		{"ipv6_only — принимаем", tproxy(FamilyIPv6Only, v6), tproxy(FamilyIPv4Only, ""), false},
		{"ipv4_only + новая IPv6-подсеть — отказ", tproxy(FamilyIPv4Only, v6), tproxy(FamilyIPv4Only, ""), true},
		{"пустой режим читается как tproxy", mode("", FamilyBoth, v6), mode("", FamilyBoth, ""), false},
		{"только IPv4-подсети — принимаем всегда", tproxy(FamilyIPv4Only, "10.0.0.0/8"), tproxy(FamilyIPv4Only, ""), false},
		{"выключение IPv6 при оставшихся IPv6-подсетях — отказ", tproxy(FamilyIPv4Only, v6), tproxy(FamilyBoth, v6), true},
		{"fakeip-tun + новая IPv6-подсеть — отказ", mode("fakeip-tun", FamilyBoth, v6), mode("fakeip-tun", FamilyBoth, ""), true},
		{"policy-tun + новая IPv6-подсеть — отказ", mode("policy-tun", FamilyBoth, v6), mode("policy-tun", FamilyBoth, ""), true},
		{"остаток после смены режима, список не менялся — пропускаем", mode("fakeip-tun", FamilyBoth, v6), mode("fakeip-tun", FamilyBoth, v6), false},
		{"остаток, но IPv6-часть изменили — отказ", mode("fakeip-tun", FamilyBoth, v6+", 2001:db8:1::/48"), mode("fakeip-tun", FamilyBoth, v6), true},
		{"остаток, поменяли только IPv4-часть — пропускаем", mode("fakeip-tun", FamilyBoth, "192.168.0.0/16, 2001:db8::/48"), mode("fakeip-tun", FamilyBoth, v6), false},
		{"остаток убрали — принимаем", mode("fakeip-tun", FamilyBoth, "10.0.0.0/8"), mode("fakeip-tun", FamilyBoth, v6), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkV6SubnetsAccepted(c.next, c.cur)
			if c.reject != (err != nil) {
				t.Fatalf("err = %v, отказ ожидался: %v", err, c.reject)
			}
			if err != nil && !errors.Is(err, ErrIPv6BypassInactive) {
				t.Errorf("отказ обязан оборачивать ErrIPv6BypassInactive: %v", err)
			}
		})
	}
}

// UpdateSettings: IPv6-подсеть при "ipv4_only" отвергается и не сохраняется —
// иначе запись молча ничего не делала бы.
func TestUpdateSettings_V6SubnetWithoutV6Layer_Rejected(t *testing.T) {
	svc := newQoSLifecycleService(t, storage.SingboxRouterSettings{WANAutoDetect: true})

	err := svc.UpdateSettings(context.Background(), storage.SingboxRouterSettings{
		WANAutoDetect:      true,
		BypassExtraSubnets: "10.0.0.0/8, 2001:db8::/48",
	})
	if !errors.Is(err, ErrIPv6BypassInactive) {
		t.Fatalf("err = %v, want ErrIPv6BypassInactive", err)
	}
	if !strings.Contains(err.Error(), "2001:db8::/48") {
		t.Errorf("в тексте отказа обязана быть названа подсеть: %v", err)
	}
	all, err := svc.deps.Settings.Load()
	if err != nil {
		t.Fatalf("Settings.Load: %v", err)
	}
	if all.SingboxRouter.BypassExtraSubnets != "" {
		t.Errorf("отвергнутый список сохранён: %q", all.SingboxRouter.BypassExtraSubnets)
	}

	// IPv4-подсети при том же режиме проходят как раньше.
	if err := svc.UpdateSettings(context.Background(), storage.SingboxRouterSettings{
		WANAutoDetect:      true,
		BypassExtraSubnets: "10.0.0.0/8",
	}); err != nil {
		t.Fatalf("IPv4-подсеть при ipv4_only обязана сохраняться: %v", err)
	}
}

// Остаток после смены режима: список принят раньше, слой больше не работает.
// Сохранение прочих настроек не упирается в старые записи, а статус говорит,
// что они не действуют.
func TestInertV6SubnetsIssue(t *testing.T) {
	sr := storage.SingboxRouterSettings{
		Enabled: true, RoutingMode: "fakeip-tun", InterceptFamily: FamilyBoth,
		BypassExtraSubnets: "10.0.0.0/8, 2001:db8::/48",
	}
	issue, ok := inertV6SubnetsIssue(sr)
	if !ok || issue.Severity != "warning" || issue.Kind != "ipv6-bypass-inert" || !strings.Contains(issue.Message, "2001:db8::/48") {
		t.Fatalf("ожидалось предупреждение с подсетью, got %+v ok=%v", issue, ok)
	}

	sr.RoutingMode = "tproxy"
	if _, ok := inertV6SubnetsIssue(sr); ok {
		t.Error("при работающем слое предупреждения быть не должно")
	}
	sr.InterceptFamily = FamilyIPv4Only
	if _, ok := inertV6SubnetsIssue(sr); !ok {
		t.Error("tproxy + ipv4_only с IPv6-подсетями — предупреждение обязательно")
	}
	sr.BypassExtraSubnets = "10.0.0.0/8"
	if _, ok := inertV6SubnetsIssue(sr); ok {
		t.Error("без IPv6-подсетей предупреждать не о чем")
	}
	sr.BypassExtraSubnets = "2001:db8::/48"
	sr.Enabled = false
	if _, ok := inertV6SubnetsIssue(sr); ok {
		t.Error("выключенный роутер — без предупреждения")
	}
}

// Отказ IPv6-половины geoip-обхода не делает сбойным статус набора: IPv4-набор
// собран и действует. Причина уходит отдельным предупреждением.
func TestStoreBypassSetOutcome_V6HalfFailureIsWarningNotError(t *testing.T) {
	svc := &ServiceImpl{}
	sr := storage.SingboxRouterSettings{
		Enabled: true, RoutingMode: "tproxy", InterceptFamily: FamilyBoth,
		BypassGeoIPTags: []string{"geoip:cn"},
	}

	svc.storeBypassSetOutcome(bypassset.PopulateResult{
		EntryCount: 7, CountOK: true,
		Err6: errors.New("populate staging: ipset restore: exit status 1"),
	}, nil)
	count, ok, _, lastErr, _ := svc.BypassSetStatus()
	if lastErr != "" {
		t.Errorf("статус набора не должен показывать сбой при собранном IPv4-наборе: %q", lastErr)
	}
	if count != 7 || !ok {
		t.Errorf("размер IPv4-набора обязан остаться фактом: %d/%v", count, ok)
	}
	issue, has := svc.bypass6Issue(sr)
	if !has || issue.Severity != "warning" || issue.Kind != "ipv6-bypass-set" || !strings.Contains(issue.Message, "ipset restore") {
		t.Fatalf("ожидалось предупреждение об IPv6-половине, got %+v has=%v", issue, has)
	}

	// Обе половины собраны: размер — сумма, предупреждение снято.
	svc.storeBypassSetOutcome(bypassset.PopulateResult{EntryCount: 7, CountOK: true, EntryCount6: 5, Count6OK: true}, nil)
	if count, ok, _, _, _ := svc.BypassSetStatus(); count != 12 || !ok {
		t.Errorf("размер обязан быть суммой по обоим наборам: %d/%v", count, ok)
	}
	if _, has := svc.bypass6Issue(sr); has {
		t.Error("после удачного наполнения предупреждение обязано уйти")
	}

	// Счётчик IPv6-набора не получен — в сумму он не входит, IPv4 остаётся фактом.
	svc.storeBypassSetOutcome(bypassset.PopulateResult{EntryCount: 7, CountOK: true, EntryCount6: 0, Count6OK: false}, nil)
	if count, ok, _, _, _ := svc.BypassSetStatus(); count != 7 || !ok {
		t.Errorf("неизвестный размер IPv6-набора не должен портить счётчик IPv4: %d/%v", count, ok)
	}
}

// Файлы правил пишутся после успешного restore, поэтому после сорванной
// установки их на диске нет — а часть правил в ядре остаться могла (restore
// коммитит по таблицам). Выключение перехвата IPv6 обязано снести слой и в
// этом случае, хотя ни снимка, ни файлов нет.
func TestReconcileInstalled_V6InstallFailedThenOff_StillUninstalls(t *testing.T) {
	svc, fe, _, sr := newV6ReconcileService(t, FamilyBoth)
	fe.restoreErr = errors.New("ip6tables-restore: line 4 failed")
	mustReconcile(t, svc, sr)
	if svc.appliedV6 != nil || fe.rulesWrites != 0 {
		t.Fatalf("сорванная установка не должна оставлять ни снимка, ни файлов: applied=%v rules=%d", svc.appliedV6 != nil, fe.rulesWrites)
	}

	sr.InterceptFamily = FamilyIPv4Only
	mustReconcile(t, svc, sr)
	if fe.cleanups != 1 || !hasCall(fe.ip6t, "-t", "mangle", "-X", Chain6Name) {
		t.Errorf("слой обязан быть снесён и без файлов правил: cleanups=%d calls=%v", fe.cleanups, fe.ip6t)
	}

	// Снесли — забыли: следующие сверки ip6tables уже не трогают.
	n := len(fe.ip6t)
	mustReconcile(t, svc, sr)
	if len(fe.ip6t) != n || fe.cleanups != 1 {
		t.Errorf("повторный снос не нужен: calls %d → %d, cleanups=%d", n, len(fe.ip6t), fe.cleanups)
	}
}

// Удаление пакета (F623) обязано снимать и перехват IPv6: его джампы в
// ip6tables, правило `ip -6 rule` и набор AWGM-BYPASS6 переживают остановку
// sing-box так же, как v4-правила, а хук 53 prerm удаляет вместе с остальными
// — без сноса устройства политики оставались бы без IPv6 до перезагрузки
// роутера. Набор — только после правил: пока в ядре стоит `--match-set`,
// ipset его не снесёт.
func TestReleaseNetfilterForRemoval_SweepsV6Layer(t *testing.T) {
	stubV6Env(t)
	fe := &v6Exec{dump: v6JumpsDump()}
	origTeardown := removalTeardownBypassSet
	removalTeardownBypassSet = func(*ServiceImpl, context.Context) {}
	callsAtDrop := -1
	origDrop := dropBypassSet6
	dropBypassSet6 = func(context.Context) error { callsAtDrop = len(fe.ip6t); return nil }
	t.Cleanup(func() { removalTeardownBypassSet, dropBypassSet6 = origTeardown, origDrop })

	ReleaseNetfilterForRemoval(context.Background(), Deps{IPTables: newV6IPTables(fe)})

	if fe.cleanups != 1 || fe.blackholeCleanups != 1 {
		t.Errorf("файлы правил, хук и блокировка IPv6 обязаны быть сняты: cleanups=%d blackhole=%d", fe.cleanups, fe.blackholeCleanups)
	}
	if !hasCall(fe.ip6t, "-t", "mangle", "-D", "PREROUTING", "-i", "br0", "-m", "mark", "--mark", "0xffffaab",
		"-m", "conntrack", "--ctdir", "ORIGINAL", "-j", Chain6Name) {
		t.Errorf("джамп перехвата IPv6 не снят: %v", fe.ip6t)
	}
	if !hasCall(fe.ip, "-6", "rule", "del", "fwmark", "0x1", "table", "100") {
		t.Errorf("правило ip -6 rule не снято: %v", fe.ip)
	}
	lastChain := -1
	for i, c := range fe.ip6t {
		if reflect.DeepEqual(c, []string{"-t", "nat", "-X", Redirect6Chain}) {
			lastChain = i
		}
	}
	if lastChain < 0 {
		t.Fatalf("цепочки перехвата IPv6 не удалены: %v", fe.ip6t)
	}
	if callsAtDrop <= lastChain {
		t.Errorf("набор AWGM-BYPASS6 снесён до снятия правил или не снесён (снос после %d вызовов, последняя цепочка — вызов %d)", callsAtDrop, lastChain)
	}
}

// Отказ сноса набора AWGM-BYPASS6 при удалении пакета обязан остаться в
// журнале, как у v4-набора: иначе сирота набора не видна никому.
func TestReleaseNetfilterForRemoval_V6SetDropError_Logged(t *testing.T) {
	stubV6Env(t)
	fe := &v6Exec{}
	origTeardown, origDrop := removalTeardownBypassSet, dropBypassSet6
	removalTeardownBypassSet = func(*ServiceImpl, context.Context) {}
	dropBypassSet6 = func(context.Context) error { return errors.New("ipset: set in use") }
	t.Cleanup(func() { removalTeardownBypassSet, dropBypassSet6 = origTeardown, origDrop })
	rec := &recordingAppLogger{}

	ReleaseNetfilterForRemoval(context.Background(), Deps{IPTables: newV6IPTables(fe), AppLog: rec})

	if !strings.Contains(strings.Join(rec.entries, "\n"), "set in use") {
		t.Errorf("ошибка сноса набора AWGM-BYPASS6 не попала в журнал: %v", rec.entries)
	}
}

// Настройки не прочитались — наполнение IPv6-половины пропущено, и причина
// обязана быть в журнале, а не проглочена: иначе набор молча пуст.
func TestRunBypassPopulate_V6SettingsReadError_Logged(t *testing.T) {
	dir := t.TempDir()
	// settings.json — каталог: чтение падает и под root.
	if err := os.Mkdir(filepath.Join(dir, "settings.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &recordingAppLogger{}
	svc := newTestService(t, Deps{AppLog: rec, Settings: storage.NewSettingsStore(dir)})
	svc.appLog = logging.NewScopedLogger(rec, logging.GroupRouting, logging.SubSingboxRouter)
	svc.populateBypassSet = func(context.Context, []string) (bypassset.PopulateResult, error) {
		return bypassset.PopulateResult{}, nil
	}

	svc.runBypassPopulate([]string{"ru"})

	if !strings.Contains(strings.Join(rec.entries, "\n"), "is a directory") {
		t.Errorf("ошибка чтения настроек не попала в журнал: %v", rec.entries)
	}
}

// Настройки прочитались до наполнения и не перечитались после: набор, только
// что наполненный по включённому перехвату, не сносится вслепую, а причина —
// в журнале.
func TestRunBypassPopulate_V6SettingsRereadError_KeepsSetAndLogs(t *testing.T) {
	env := stubV6Env(t)
	rec := &recordingAppLogger{}
	svc := newTestService(t, Deps{AppLog: rec, Settings: newTestSettingsStore(t, storage.SingboxRouterSettings{InterceptFamily: FamilyBoth})})
	svc.appLog = logging.NewScopedLogger(rec, logging.GroupRouting, logging.SubSingboxRouter)
	broken := t.TempDir()
	if err := os.Mkdir(filepath.Join(broken, "settings.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	svc.populateBypassSet = func(context.Context, []string) (bypassset.PopulateResult, error) {
		// Пока шло наполнение, хранилище перестало читаться.
		svc.deps.Settings = storage.NewSettingsStore(broken)
		return bypassset.PopulateResult{}, nil
	}

	svc.runBypassPopulate([]string{"ru"})

	if env.setDropped != 0 {
		t.Errorf("набор не должен сноситься по нечитаемым настройкам: dropped=%d", env.setDropped)
	}
	if !strings.Contains(strings.Join(rec.entries, "\n"), "не перечитаны") {
		t.Errorf("ошибка повторного чтения настроек не попала в журнал: %v", rec.entries)
	}
}

// Снос набора AWGM-BYPASS6 убирает и его дамп — по нему хук netfilter.d
// пересоздаёт набор, и оставшийся дамп воскрешал бы его на каждой перестройке
// файрвола. Порядок «сначала дамп» (как в teardownBypassSet) здесь не
// проверить без настоящего ipset; проверяем, что дамп удалён и что
// отсутствующий дамп — не ошибка.
func TestDropBypassSet6_RemovesDump(t *testing.T) {
	if bypassset.IPSetBinary() != "" {
		t.Skip("на хосте есть ipset — боевой снос набора в тесте не зовём")
	}
	orig := bypassSave6Path
	bypassSave6Path = filepath.Join(t.TempDir(), "bypass6.ipset")
	t.Cleanup(func() { bypassSave6Path = orig })
	if err := os.WriteFile(bypassSave6Path, []byte("create AWGM-BYPASS6 hash:net family inet6\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := realDropBypassSet6(context.Background()); err != nil {
		t.Fatalf("снос набора: %v", err)
	}
	if _, err := os.Stat(bypassSave6Path); !os.IsNotExist(err) {
		t.Errorf("дамп набора обязан быть удалён, stat: %v", err)
	}
	if err := realDropBypassSet6(context.Background()); err != nil {
		t.Errorf("повторный снос без дампа не должен быть ошибкой: %v", err)
	}
}
