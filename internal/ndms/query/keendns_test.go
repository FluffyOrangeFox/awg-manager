package query

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hoaxisr/awg-manager/internal/ndms/transport"
)

// На современной прошивке /show/ndns отдаёт booked + domain раздельно;
// доменом для доступа служит их склейка booked.domain.
func TestKeenDNSFetch_BuildsFQDNFromBookedAndDomain(t *testing.T) {
	g := NewFakeGetter()
	g.SetRaw("/show/ndns", []byte(`{"name":"example","booked":"example","domain":"crazedns.ru","address":"203.0.113.72"}`))
	s := NewKeenDNSStore(g, NopLogger())

	info, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if info == nil || info.Domain != "example.crazedns.ru" {
		t.Fatalf("Domain=%v want example.crazedns.ru", info)
	}
}

// Регрессия #376: дёргаем ТОЛЬКО /show/ndns, легаси-пути больше не зондируем
// (иначе они 404'ят и спамят журналы awgm и keenetic).
func TestKeenDNSFetch_OnlyQueriesShowNdns(t *testing.T) {
	g := NewFakeGetter()
	g.SetRaw("/show/ndns", []byte(`{"booked":"","domain":""}`)) // KeenDNS не настроен
	s := NewKeenDNSStore(g, NopLogger())

	info, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if info != nil {
		t.Fatalf("info=%v want nil (не настроено)", info)
	}
	if n := g.Calls("/show/sc/ndns"); n != 0 {
		t.Errorf("/show/sc/ndns вызван %d раз, ожидалось 0", n)
	}
	if n := g.Calls("/show/ip/dns/domain"); n != 0 {
		t.Errorf("/show/ip/dns/domain вызван %d раз, ожидалось 0", n)
	}
}

// 404 на /show/ndns = подсистема KeenDNS отсутствует на этой OS → «не
// настроено», а не ошибка (чтобы поллер не сыпал ошибками каждый тик).
func TestKeenDNSFetch_NotFoundIsNotError(t *testing.T) {
	g := NewFakeGetter()
	g.SetError("/show/ndns", &transport.HTTPError{Method: "GET", Path: "/show/ndns", Status: http.StatusNotFound})
	s := NewKeenDNSStore(g, NopLogger())

	info, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("404 должен трактоваться как nil,nil, получили err: %v", err)
	}
	if info != nil {
		t.Fatalf("info=%v want nil", info)
	}
}

// После 404 подсистемы на этой прошивке нет, и спрашивать её повторно незачем:
// истёкший TTL кэша не должен возвращать нас в RCI. Без защёлки заведомо
// провальный GET уходил раз в минуту и каждый писал ERROR в журнал.
func TestKeenDNSFetch_NotFoundBacksOffAndHeals(t *testing.T) {
	g := NewFakeGetter()
	g.SetError("/show/ndns", &transport.HTTPError{Method: "GET", Path: "/show/ndns", Status: http.StatusNotFound})
	s := NewKeenDNSStore(g, NopLogger())

	if _, err := s.Get(context.Background()); err != nil {
		t.Fatalf("первый Get: %v", err)
	}
	s.InvalidateAll() // эквивалент истёкшего TTL

	info, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("второй Get: %v", err)
	}
	if info != nil {
		t.Fatalf("info=%v want nil", info)
	}
	if n := g.Calls("/show/ndns"); n != 1 {
		t.Errorf("/show/ndns запрошен %d раз, ожидался 1 (бэкофф)", n)
	}

	// Бэкофф не вечен: прошивка с живой подсистемой обязана вылечиться сама.
	// Вечная защёлка на ложном 404 стартового окна заперла бы KeenDNS до
	// перезапуска демона, и выданные клиентам .conf ушли бы с WAN-адресом.
	s.absentMu.Lock()
	s.absentUntil = time.Now().Add(-time.Second)
	s.absentMu.Unlock()
	g.SetError("/show/ndns", nil) // подсистема отвечает
	g.SetRaw("/show/ndns", []byte(`{"booked":"example","domain":"crazedns.ru"}`))
	s.InvalidateAll()

	info, err = s.Get(context.Background())
	if err != nil {
		t.Fatalf("после истечения бэкоффа: %v", err)
	}
	if info == nil || info.Domain != "example.crazedns.ru" {
		t.Errorf("info=%v — бэкофф не истёк, подсистема заперта навсегда", info)
	}
}

// Режим доступа: имя годится как адрес туннеля или ссылки ТОЛЬКО при прямом
// доступе (F389, F392). Полярность fail-safe — всё, что не `direct`, включая
// незнакомое и пустое, значит «через прокси NDMS, порт не пройдёт».
func TestKeenDNS_AccessGate(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"прямой доступ", `{"booked":"example","domain":"crazedns.ru","access":"direct"}`, true},
		{"через прокси", `{"booked":"example","domain":"crazedns.ru","access":"cloud"}`, false},
		{"режим не пришёл", `{"booked":"example","domain":"crazedns.ru"}`, false},
		{"незнакомое значение", `{"booked":"example","domain":"crazedns.ru","access":"whatever"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := parseKeenDNS([]byte(tc.raw))
			if info == nil {
				t.Fatal("разбор вернул nil")
			}
			if got := info.DirectAccess(); got != tc.want {
				t.Errorf("DirectAccess() = %v, want %v (access=%q)", got, tc.want, info.Access)
			}
		})
	}
	// nil-приёмник — тот же ответ: вызывающий не обязан проверять сам.
	var absent *KeenDNSInfo
	if absent.DirectAccess() {
		t.Error("у отсутствующего KeenDNS прямого доступа быть не может")
	}
}

// Фикстура — ответ GET /rci/show/ndns с живого роутера (Keenetic Ultra
// KN-1811, KeeneticOS 5.2 Beta 0; прямого доступа по имени на нём нет —
// `access` пуст, `ttp.direct` = false). Набор ключей и типы значений сняты
// как есть; ВСЕ значения, относящиеся к конкретному роутеру, заменены: имя,
// зона, xns, имя WAN-интерфейса и адреса (на документационные диапазоны).
//
// Фиксирует две вещи. Ключ `address6` стоит на верхнем уровне рядом с
// `address` — его и читает разбор. И адреса в `ttp` — это адреса
// WAN-интерфейса для облачного туннеля, а не адрес доступа по имени: в обход
// пресета keendns они попадать не должны.
func TestParseKeenDNS_RealShowNdnsResponse(t *testing.T) {
	raw, err := os.ReadFile("testdata/show_ndns_kn1811.json")
	if err != nil {
		t.Fatal(err)
	}

	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("фикстура — невалидный JSON: %v", err)
	}
	for _, k := range []string{"booked", "domain", "address", "address6", "access", "access6"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("в ответе show ndns нет ключа верхнего уровня %q", k)
		}
	}

	info := parseKeenDNS(raw)
	if info == nil {
		t.Fatal("разбор вернул nil")
	}
	if info.Domain != "myrouter.keenetic.pro" || !info.Enabled {
		t.Errorf("Domain=%q Enabled=%v, want myrouter.keenetic.pro/true", info.Domain, info.Enabled)
	}
	// Прямого доступа нет: адреса доступа пусты в обоих семействах, и адреса
	// из `ttp` на их место не подставляются.
	if info.Address != "" || info.Address6 != "" {
		t.Errorf("Address=%q Address6=%q, want оба пустые (адреса ttp — не адрес доступа)", info.Address, info.Address6)
	}
	if info.DirectAccess() {
		t.Error("пустой access — не прямой доступ")
	}
}

// Прямой доступ: `address` и `address6` заполнены — оба доходят до вызывающего.
// Значения синтетические (на стендовом роутере прямого доступа нет), ключи —
// те же, что в настоящем ответе выше.
func TestParseKeenDNS_DirectAccessAddresses(t *testing.T) {
	info := parseKeenDNS([]byte(`{"booked":"example","domain":"keenetic.pro","address":"203.0.113.72","address6":" 2001:db8::72 ","access":"direct","access6":"direct"}`))
	if info == nil {
		t.Fatal("разбор вернул nil")
	}
	if info.Address != "203.0.113.72" || info.Address6 != "2001:db8::72" {
		t.Errorf("Address=%q Address6=%q", info.Address, info.Address6)
	}
}
