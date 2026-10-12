package router

import (
	"context"
	"errors"
	"strings"
	"testing"

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
}

func stubV6Env(t *testing.T) *v6Env {
	t.Helper()
	env := &v6Env{
		topo:  v6Topology{Bridges: []string{"br0"}, LocalCIDRs: []string{"2001:db8:1::/64"}},
		bound: true,
	}
	oldTopo, oldProbe, oldFile := collectV6Topology, v6SocketsProbe, v6RulesFilePresent
	oldEnsure, oldDrop := ensureBypassSet6, dropBypassSet6
	oldBH := blackhole6FilePresent
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
	svc.deps.IPTables.runIP6TablesOut = func(context.Context, ...string) (string, error) { calls++; return "", nil }
	mustReconcile(t, svc, sr)
	mustReconcile(t, svc, sr)
	if calls != 0 || len(fe.ip6t) != 0 || len(fe.restores) != 0 || fe.cleanups != 0 {
		t.Errorf("выключенный слой не должен трогать ip6tables: out=%d, run=%d, restore=%d, cleanup=%d",
			calls, len(fe.ip6t), len(fe.restores), fe.cleanups)
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
	svc.deps.IPTables.restoreNoflush6 = func(_ context.Context, in string) error {
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
	svc.deps.IPTables.restoreNoflush6 = func(_ context.Context, in string) error {
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
	svc.deps.IPTables.restoreNoflush6 = func(_ context.Context, in string) error {
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
