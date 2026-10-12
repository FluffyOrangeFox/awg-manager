package router

import (
	"context"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/hoaxisr/awg-manager/internal/storage"
)

// Паритет v6-слоя с v4: исключения по подсетям и geoip-набору, классы QoS,
// интерфейсы-источники, сброс старых потоков.

// Полный обход (подсети и набор) стоит в САМОМ начале обеих цепочек — выше
// перехвата DNS: исключённая подсеть не должна попадать в sing-box даже своим
// DNS, это та же семантика, что у v4.
func TestBuildRestoreInput6_UserBypassBeforeDNS(t *testing.T) {
	spec := testV6Spec()
	spec.BypassCIDRs = []string{"2001:db8:aa::/48"}
	spec.BypassGeoIPSet = true

	mangle := buildMangleRestoreInput6(spec)
	cidr := indexOf(t, mangle, "-A AWGM6-TPROXY -d 2001:db8:aa::/48 -j RETURN")
	set := indexOf(t, mangle, "-A AWGM6-TPROXY -m set --match-set AWGM-BYPASS6 dst -j RETURN")
	dns := indexOf(t, mangle, "-p udp --dport 53 -j TPROXY")
	if !(cidr < set && set < dns) {
		t.Errorf("mangle: полный обход обязан стоять выше перехвата DNS:\n%s", mangle)
	}

	nat := buildNatRestoreInput6(spec)
	cidr = indexOf(t, nat, "-A AWGM6-REDIRECT -d 2001:db8:aa::/48 -j RETURN")
	set = indexOf(t, nat, "-A AWGM6-REDIRECT -m set --match-set AWGM-BYPASS6 dst -j RETURN")
	catchAll := indexOf(t, nat, "-p tcp -j REDIRECT")
	if !(cidr < set && set < catchAll) {
		t.Errorf("nat: полный обход обязан стоять выше catch-all:\n%s", nat)
	}

	// Без набора правила с `-m set` быть не должно: на отсутствующий набор
	// ip6tables-restore падает целиком.
	spec.BypassGeoIPSet = false
	if strings.Contains(buildRestoreInput6(spec), "--match-set") {
		t.Error("без geoip-тегов правила с набором быть не должно")
	}
}

// Классы QoS: диспатч по DSCP стоит после исключений по адресам и перед
// catch-all (иначе безусловный TPROXY/REDIRECT съел бы пакет раньше), а в nat
// перед ним — вырезка TCP/53 на основной порт.
func TestBuildRestoreInput6_QoSDispatch(t *testing.T) {
	spec := testV6Spec()
	tp6, rp6 := QoSClassPorts6(2)
	spec.QoSClasses = []QoSClassSpec{{DSCP: 46, TProxyPort: tp6, RedirectPort: rp6}}

	mangle := buildMangleRestoreInput6(spec)
	dns := indexOf(t, mangle, "-i br0 -p udp --dport 53 -j TPROXY --on-port 51321")
	excl := indexOf(t, mangle, "-A AWGM6-TPROXY -d fe80::/10 -j RETURN")
	class := indexOf(t, mangle, "-A AWGM6-TPROXY -p udp -m dscp --dscp 46 -j TPROXY --on-port 51343 --on-ip ::1 --tproxy-mark 0x1")
	catchAll := indexOf(t, mangle, "-A AWGM6-TPROXY -i br0 -p udp -j TPROXY --on-port 51321")
	if !(dns < excl && excl < class && class < catchAll) {
		t.Errorf("mangle: порядок DNS → исключения → класс → catch-all нарушен:\n%s", mangle)
	}

	nat := buildNatRestoreInput6(spec)
	dnsTCP := indexOf(t, nat, "-A AWGM6-REDIRECT -p tcp --dport 53 -j REDIRECT --to-ports 51273")
	classTCP := indexOf(t, nat, "-A AWGM6-REDIRECT -p tcp -m dscp --dscp 46 -j REDIRECT --to-ports 51363")
	catchAllTCP := indexOf(t, nat, "-A AWGM6-REDIRECT -p tcp -j REDIRECT --to-ports 51273")
	if !(dnsTCP < classTCP && classTCP < catchAllTCP) {
		t.Errorf("nat: порядок TCP/53 → класс → catch-all нарушен:\n%s", nat)
	}

	// Без классов вырезки TCP/53 нет — её ловит catch-all.
	spec.QoSClasses = nil
	if strings.Contains(buildNatRestoreInput6(spec), "--dport 53") {
		t.Error("без классов QoS вырезка TCP/53 не нужна")
	}
}

// Интерфейсы-источники: у каждого свой джамп без метки (метки по MAC у
// туннеля нет), а UDP идёт в общий инбаунд без привязки к интерфейсу.
func TestBuildRestoreInput6_IngressInterfaces(t *testing.T) {
	spec := testV6Spec()
	spec.IngressInterfaces = []string{"nwg3"}
	got := buildRestoreInput6(spec)
	for _, want := range []string{
		"-A AWGM6-TPROXY -i nwg3 -p udp --dport 53 -j TPROXY --on-port 51274 --on-ip ::1",
		"-A AWGM6-TPROXY -i nwg3 -p udp -j TPROXY --on-port 51274 --on-ip ::1",
		"-A PREROUTING -i nwg3 -m conntrack --ctdir ORIGINAL -j AWGM6-TPROXY",
		"-A PREROUTING -i nwg3 -j AWGM6-REDIRECT",
		// Мост при этом остаётся со своей меткой и своим портом.
		"-A PREROUTING -i br0 -m mark --mark 0xffffaab -m conntrack --ctdir ORIGINAL -j AWGM6-TPROXY",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("нет %q:\n%s", want, got)
		}
	}

	// Только источники, мостов с IPv6 нет: перехват всё равно есть.
	only := V6Spec{PolicyMark: "0xffffaab", IngressInterfaces: []string{"nwg3"}}
	if !v6HasJumps(only) || v6BridgeJumps(only) {
		t.Error("спек с одними источниками обязан иметь джампы, но не джампы мостов")
	}
}

// Инбаунды под источники: общий tproxy6-in без bind_interface появляется
// только вместе с ними.
func TestEnsureV6Inbounds_IngressGenericInbound(t *testing.T) {
	spec := testV6Spec()
	in, _ := ensureV6Inbounds(nil, spec, true, "", 0)
	for _, i := range in {
		if i.Tag == tproxy6Tag0 {
			t.Fatal("без интерфейсов-источников общий инбаунд не нужен")
		}
	}
	spec.IngressInterfaces = []string{"nwg3"}
	in, changed := ensureV6Inbounds(in, spec, true, "", 0)
	if !changed {
		t.Fatal("появление источника обязано менять инбаунды")
	}
	var generic *Inbound
	for i := range in {
		if in[i].Tag == tproxy6Tag0 {
			generic = &in[i]
		}
	}
	if generic == nil {
		t.Fatalf("общий инбаунд не добавлен: %+v", in)
	}
	if generic.ListenPort != TProxy6Port || generic.BindInterface != "" || generic.Listen != "::1" || generic.Network != "udp" {
		t.Errorf("общий инбаунд не канонический: %+v", *generic)
	}
}

// buildV6Spec: подсети делятся по семействам, набор включается тегами,
// источник-мост не дублируется.
func TestBuildV6Spec_ParityInputs(t *testing.T) {
	sr := storage.SingboxRouterSettings{
		BypassExtraSubnets: "10.9.9.0/24, 2001:db8:aa::/48",
		BypassGeoIPTags:    []string{"geoip:cn"},
	}
	topo := v6Topology{Bridges: []string{"br0"}}
	spec, _ := buildV6Spec(sr, "0xffffaab", true, topo, []string{"nwg3", "br0"}, []string{"2001:db8:cd::1/128", "2001:db8:aa::/48"})

	// Рантайм-исключения (адреса KeenDNS) идут первыми, пользовательские — за
	// ними, дубль между списками схлопывается; IPv4-запись сюда не попадает.
	if want := []string{"2001:db8:cd::1/128", "2001:db8:aa::/48"}; !reflect.DeepEqual(spec.BypassCIDRs, want) {
		t.Errorf("BypassCIDRs = %v, want %v", spec.BypassCIDRs, want)
	}
	if !spec.BypassGeoIPSet {
		t.Error("geoip-теги обязаны включать набор")
	}
	if !reflect.DeepEqual(spec.IngressInterfaces, []string{"nwg3"}) {
		t.Errorf("IngressInterfaces = %v, want [nwg3] (мост уже покрыт своими правилами)", spec.IngressInterfaces)
	}
}

// Сброс потоков: в режиме политики — по connmark политики (десятичной), в
// режиме «все устройства» — все UDP-записи IPv6. Неразбираемая метка — отказ,
// а не снос всего подряд.
func TestEvictArgs6(t *testing.T) {
	args, ok := evictArgs6(V6Spec{PolicyMark: "0xffffaab"})
	if !ok || !reflect.DeepEqual(args, []string{"-D", "-f", "ipv6", "-p", "udp", "--mark", "268434091"}) {
		t.Errorf("политика: %v, %v", args, ok)
	}
	args, ok = evictArgs6(V6Spec{MatchAll: true})
	if !ok || !reflect.DeepEqual(args, []string{"-D", "-f", "ipv6", "-p", "udp"}) {
		t.Errorf("все устройства: %v, %v", args, ok)
	}
	if _, ok := evictArgs6(V6Spec{PolicyMark: "мусор"}); ok {
		t.Error("неразбираемая метка обязана давать отказ")
	}
}

// Хук: набор возвращается до ip6tables-restore, а после восстановления mangle
// сбрасываются старые потоки — по метке из живого джампа или, без неё, все.
func TestNetfilter6HookScript_SetAndEviction(t *testing.T) {
	script := netfilter6HookScript()
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("сгенерированный хук — невалидный sh: %v\n%s", err, out)
	}
	create := indexOf(t, script, "ipset create AWGM-BYPASS6 hash:net maxelem 262144 family inet6")
	restoreSet := indexOf(t, script, "ipset restore -exist")
	restoreRules := indexOf(t, script, "ip6tables-restore --noflush")
	if !(create < restoreSet && restoreSet < restoreRules) {
		t.Errorf("набор обязан вернуться до ip6tables-restore:\n%s", script)
	}
	for _, want := range []string{
		`-D -f ipv6 -p udp --mark "$(printf '%d' "$pmark")"`,
		`"$CT" -D -f ipv6 -p udp >/dev/null`,
		"xt_dscp", "xt_set",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("в хуке нет %q:\n%s", want, script)
		}
	}
}

// IPv6-пара инбаундов класса QoS появляется только при V6 и без привязки к
// интерфейсу; теги остаются в зарезервированном пространстве qos-*.
func TestEnsureQoSInbounds_V6Pair(t *testing.T) {
	classes := activeQoSClasses([]storage.SingboxQoSClass{{DSCP: 46, Outbound: "vpn", Enabled: true, Slot: 2}})
	v4only, _ := ensureQoSInbounds(nil, classes, "", 0)
	if len(v4only) != 2 {
		t.Fatalf("без V6 у класса одна пара инбаундов, got %d", len(v4only))
	}

	classes[0].V6 = true
	both, changed := ensureQoSInbounds(v4only, classes, "", 0)
	if !changed || len(both) != 4 {
		t.Fatalf("с V6 у класса две пары: changed=%v len=%d", changed, len(both))
	}
	udp, tcp := both[2], both[3]
	if udp.Tag != "tproxy-qos-46-v6" || udp.Listen != "::1" || udp.ListenPort != 51343 || udp.BindInterface != "" || udp.Network != "udp" {
		t.Errorf("UDP-инбаунд IPv6 не канонический: %+v", udp)
	}
	if tcp.Tag != "redirect-qos-46-v6" || tcp.Listen != "::" || tcp.ListenPort != 51363 {
		t.Errorf("TCP-инбаунд IPv6 не канонический: %+v", tcp)
	}
	if !isQoSInboundTag(udp.Tag) || !isQoSInboundTag(tcp.Tag) {
		t.Error("теги IPv6-пары обязаны оставаться в зарезервированном пространстве qos-*")
	}
	// Идемпотентность и обратный ход.
	if _, changed := ensureQoSInbounds(both, classes, "", 0); changed {
		t.Error("повторный вызов не должен ничего менять")
	}
	classes[0].V6 = false
	if back, _ := ensureQoSInbounds(both, classes, "", 0); len(back) != 2 {
		t.Errorf("выключение перехвата IPv6 обязано убрать IPv6-пару, осталось %d", len(back))
	}
}

// Управляемые правила маршрутизации класса включают IPv6-инбаунды — иначе
// помеченный DSCP трафик IPv6 попал бы в инбаунд класса и ушёл по общим
// правилам, а не в outbound класса.
func TestBuildQoSRouteRules_V6Inbounds(t *testing.T) {
	classes := activeQoSClasses([]storage.SingboxQoSClass{{DSCP: 46, Outbound: "vpn", Enabled: true}})
	classes[0].V6 = true
	rules := buildQoSRouteRules(classes, storage.SingboxRouterSettings{SnifferEnabled: true})

	var route *Rule
	for i := range rules {
		if rules[i].Action == "route" {
			route = &rules[i]
		}
	}
	if route == nil {
		t.Fatal("нет правила route для класса")
	}
	want := []string{"tproxy-qos-46", "redirect-qos-46", "tproxy-qos-46-v6", "redirect-qos-46-v6"}
	if !reflect.DeepEqual(route.Inbound, want) {
		t.Errorf("Inbound = %v, want %v", route.Inbound, want)
	}
	for _, r := range rules {
		if r.Action == "route-options" && !reflect.DeepEqual(r.Inbound, []string{"tproxy-qos-46", "tproxy-qos-46-v6"}) {
			t.Errorf("route-options обязан покрывать оба UDP-инбаунда: %v", r.Inbound)
		}
	}
}

// qosClassesFor: IPv6-пара — только в режиме tproxy, только при перехвате IPv6
// и только если в ядре есть IPv6 (инбаунд на `::` иначе уронил бы весь конфиг).
func TestQoSClassesFor(t *testing.T) {
	old := ipv6StackPresent
	t.Cleanup(func() { ipv6StackPresent = old })
	stack := true
	ipv6StackPresent = func() bool { return stack }

	base := storage.SingboxRouterSettings{
		QoSClasses: []storage.SingboxQoSClass{{DSCP: 46, Outbound: "vpn", Enabled: true}},
	}
	cases := []struct {
		name   string
		mode   string
		family string
		stack  bool
		want   bool
	}{
		{"tproxy + both", "tproxy", FamilyBoth, true, true},
		{"режим не задан + ipv6_only", "", FamilyIPv6Only, true, true},
		{"ipv4_only", "tproxy", FamilyIPv4Only, true, false},
		{"policy-tun", "policy-tun", FamilyBoth, true, false},
		{"нет IPv6 в ядре", "tproxy", FamilyBoth, false, false},
	}
	for _, c := range cases {
		sr := base
		sr.RoutingMode, sr.InterceptFamily = c.mode, c.family
		stack = c.stack
		got := qosClassesFor(sr)
		if len(got) != 1 || got[0].V6 != c.want {
			t.Errorf("%s: V6 = %v, want %v", c.name, got, c.want)
		}
		if specs := qosIPTablesSpecs6(got); (len(specs) == 1) != c.want {
			t.Errorf("%s: qosIPTablesSpecs6 = %v", c.name, specs)
		}
	}
}

// Порты IPv6-пар не пересекаются ни с IPv4-парами, ни с остальными портами
// слоя.
func TestV6ListenPorts_NoCollisions(t *testing.T) {
	seen := map[int]bool{}
	for _, p := range routerListenPorts() {
		if seen[p] {
			t.Errorf("порт %d занят дважды", p)
		}
		seen[p] = true
	}
}

// Аппаратное ускорение: после восстановления mangle хук сбрасывает таблицу
// PPE — соединения, установленные до правил, идут мимо netfilter, и без сброса
// ни правила, ни снос conntrack их не возвращают.
func TestNetfilter6HookScript_FlushesOffload(t *testing.T) {
	script := netfilter6HookScript()
	flush := indexOf(t, script, "[ -w /proc/sys/net/hwnat/ppe_flush ] && echo 1 > /proc/sys/net/hwnat/ppe_flush")
	restore := indexOf(t, script, "ip6tables-restore --noflush")
	if flush < restore {
		t.Errorf("сброс ускорения обязан идти после возврата правил:\n%s", script)
	}
}

// Аплинки берутся из маршрутов по умолчанию всех таблиц; lo — не аплинк (через
// него идёт наш же `local ::/0` таблицы TPROXY и недостижимые заглушки ядра).
func TestParseIPv6DefaultIfaces(t *testing.T) {
	const z = "00000000000000000000000000000000"
	data := z + " 00 " + z + " 00 fe8000000000000002005efffe005303 000003e8 00000001 00000000 00000003     ppp0\n" +
		z + " 00 " + z + " 00 " + z + " 000003e8 00000001 00000000 00000001     t2s0\n" +
		z + " 00 " + z + " 00 " + z + " ffffffff 00000001 00000000 00200200       lo\n" +
		"20010db8000100000000000000000000 40 " + z + " 00 " + z + " 00000100 00000001 00000000 00000001      br0\n" +
		"мусор\n"
	got := parseIPv6DefaultIfaces(data)
	if want := []string{"ppp0", "t2s0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("parseIPv6DefaultIfaces = %v, want %v", got, want)
	}
}

// Аплинки попадают в спек только в режиме «все устройства»; в режиме политики
// джампы привязаны к мостам, и отсекать нечего. Источники — наоборот.
func TestBuildV6Spec_UplinksOnlyInMatchAll(t *testing.T) {
	topo := v6Topology{Bridges: []string{"br0"}, Uplinks: []string{"ppp0"}}
	all, _ := buildV6Spec(storage.SingboxRouterSettings{}, "", false, topo, []string{"nwg3"}, nil)
	if !all.MatchAll || !reflect.DeepEqual(all.Uplinks, []string{"ppp0"}) || len(all.IngressInterfaces) != 0 {
		t.Errorf("все устройства: %+v", all)
	}
	pol, _ := buildV6Spec(storage.SingboxRouterSettings{}, "0xffffaab", true, topo, []string{"nwg3"}, nil)
	if pol.MatchAll || len(pol.Uplinks) != 0 || !reflect.DeepEqual(pol.IngressInterfaces, []string{"nwg3"}) {
		t.Errorf("политика: %+v", pol)
	}
}

// Блокировка — зеркало v4: те же исключения, что у перехвата (полный обход,
// порты ОБОИХ протоколов, адреса роутера и LAN), терминальный DROP и тот же
// селектор джампа. Ни одного перехватывающего правила.
func TestBuildBlackholeRestoreInput6(t *testing.T) {
	spec := testV6Spec()
	spec.BypassCIDRs = []string{"2001:db8:aa::/48"}
	spec.BypassGeoIPSet = true
	spec.BypassUDPPorts = []PortRange{{From: 123, To: 123}}
	spec.BypassTCPPorts = []PortRange{{From: 22, To: 22}}
	got := buildBlackholeRestoreInput6(spec)

	user := indexOf(t, got, "-A AWGM6-BLACKHOLE -d 2001:db8:aa::/48 -j RETURN")
	set := indexOf(t, got, "-A AWGM6-BLACKHOLE -m set --match-set AWGM-BYPASS6 dst -j RETURN")
	udp := indexOf(t, got, "-A AWGM6-BLACKHOLE -p udp --dport 123 -j RETURN")
	tcp := indexOf(t, got, "-A AWGM6-BLACKHOLE -p tcp --dport 22 -j RETURN")
	ll := indexOf(t, got, "-A AWGM6-BLACKHOLE -d fe80::/10 -j RETURN")
	lan := indexOf(t, got, "-A AWGM6-BLACKHOLE -d 2001:db8:1::/64 -j RETURN")
	drop := indexOf(t, got, "-A AWGM6-BLACKHOLE -j DROP")
	jump := indexOf(t, got, "-A PREROUTING -i br0 -m mark --mark 0xffffaab -m conntrack --ctdir ORIGINAL -j AWGM6-BLACKHOLE")
	if !(user < set && set < udp && udp < tcp && tcp < ll && ll < lan && lan < drop && drop < jump) {
		t.Errorf("нарушен порядок правил блокировки:\n%s", got)
	}
	if strings.Contains(got, "TPROXY") || strings.Contains(got, "REDIRECT") || strings.Contains(got, "*nat") {
		t.Errorf("блокировка — только DROP в mangle:\n%s", got)
	}

	// Селектор блокировки и перехвата совпадает по построению — в обоих режимах.
	all := V6Spec{MatchAll: true, Bridges: spec.Bridges, Uplinks: []string{"ppp0"}}
	bh := buildBlackholeRestoreInput6(all)
	for _, want := range []string{
		"-A AWGM6-BLACKHOLE -i lo -j RETURN",
		"-A AWGM6-BLACKHOLE -i ppp0 -j RETURN",
		"-A PREROUTING -m conntrack --ctdir ORIGINAL -j AWGM6-BLACKHOLE",
	} {
		if !strings.Contains(bh, want) {
			t.Errorf("все устройства: нет %q:\n%s", want, bh)
		}
	}

	// Сравнение — по рендеру блокировки: классы QoS в неё не входят.
	a, b := testV6Spec(), testV6Spec()
	b.QoSClasses = []QoSClassSpec{{DSCP: 46, TProxyPort: 51341, RedirectPort: 51361}}
	if !equalBlackholeSpec6(&a, &b) {
		t.Error("классы QoS не должны менять спек блокировки")
	}
	b.LocalCIDRs = []string{"2001:db8:2::/64"}
	if equalBlackholeSpec6(&a, &b) {
		t.Error("смена исключений обязана менять спек блокировки")
	}
}

func TestInstallAndRemoveBlackhole6(t *testing.T) {
	fe := &v6Exec{dump: "-A PREROUTING -i br0 -m mark --mark 0xffffaab -m conntrack --ctdir ORIGINAL -j " + Blackhole6Chain + "\n"}
	it := newV6IPTables(fe)
	spec := testV6Spec()

	if err := it.InstallBlackhole6(context.Background(), spec); err != nil {
		t.Fatalf("InstallBlackhole6: %v", err)
	}
	if len(fe.restores) != 1 || fe.restores[0] != buildBlackholeRestoreInput6(spec) {
		t.Fatalf("restore обязан получить рендер блокировки, got %d вызов(ов)", len(fe.restores))
	}
	// Прежний джамп снят до restore, файл правил и хук записаны: по ним
	// DEAD-ветка хука вернёт блокировку после перестройки файрвола.
	if !hasCall(fe.ip6t, "-t", "mangle", "-D", "PREROUTING", "-i", "br0", "-m", "mark", "--mark", "0xffffaab",
		"-m", "conntrack", "--ctdir", "ORIGINAL", "-j", Blackhole6Chain) {
		t.Errorf("прежний джамп блокировки не снят: %v", fe.ip6t)
	}
	if fe.blackholeWrites != 1 || fe.hookWrites != 1 {
		t.Errorf("blackholeWrites=%d hookWrites=%d, want 1, 1", fe.blackholeWrites, fe.hookWrites)
	}
	if len(fe.ip) != 0 {
		t.Errorf("блокировке не нужны ни правило маршрутизации, ни маршрут: %v", fe.ip)
	}

	it.RemoveBlackhole6(context.Background())
	if fe.blackholeCleanups != 1 || !hasCall(fe.ip6t, "-t", "mangle", "-X", Blackhole6Chain) {
		t.Errorf("блокировка не снята: cleanups=%d calls=%v", fe.blackholeCleanups, fe.ip6t)
	}

	// Снос слоя снимает и блокировку.
	fe2 := &v6Exec{}
	newV6IPTables(fe2).Uninstall6(context.Background())
	if fe2.blackholeCleanups != 1 {
		t.Errorf("Uninstall6 обязан снимать блокировку: cleanups=%d", fe2.blackholeCleanups)
	}
}

// Адреса KeenDNS приходят с роутера одним списком; обход раскладывается по
// семействам — IPv4 в правила iptables, IPv6 в правила v6-слоя.
func TestSetKeenDNSBypass_SplitsFamilies(t *testing.T) {
	svc := &ServiceImpl{}
	svc.setKeenDNSBypass([]string{"198.51.100.11", "2001:2::c633:640b", "мусор", "::ffff:203.0.113.5"})
	if want := []string{"198.51.100.11/32", "203.0.113.5/32"}; !reflect.DeepEqual(svc.keenDNSBypass(), want) {
		t.Errorf("IPv4: %v, want %v", svc.keenDNSBypass(), want)
	}
	if want := []string{"2001:2::c633:640b/128"}; !reflect.DeepEqual(svc.keenDNSBypass6(), want) {
		t.Errorf("IPv6: %v, want %v", svc.keenDNSBypass6(), want)
	}
	svc.setKeenDNSBypass(nil)
	if len(svc.keenDNSBypass()) != 0 || len(svc.keenDNSBypass6()) != 0 {
		t.Error("пустой список обязан снимать обход в обоих семействах")
	}
}
