package bypassset

import (
	"context"
	"fmt"
	"net"
	"strings"

	sysexec "github.com/hoaxisr/awg-manager/internal/sys/exec"
)

// IPv6-близнец набора обхода. Отдельный набор, а не общий: hash:net хранит
// одно семейство, и правило ip6tables может ссылаться только на набор inet6.
// Наполняется тем же проходом по .dat, что и AWGM-BYPASS (Populate), но
// существует только при включённом перехвате IPv6 — его жизненным циклом
// владеет v6-слой роутера (internal/singbox/router/iptables6.go).
const (
	// SetName6 — набор, на который ссылаются правила ip6tables.
	SetName6 = "AWGM-BYPASS6"
	// StagingSetName6 — его черновик для атомарной пересборки.
	StagingSetName6 = "AWGM-BYPASS6-STG"

	familyInet  = "inet"
	familyInet6 = "inet6"
)

// CreateSet6 создаёт AWGM-BYPASS6, если его ещё нет. Идемпотентно.
func CreateSet6(ctx context.Context) error {
	return createNamedSetFamily(ctx, SetName6, familyInet6)
}

// DestroySet6 сносит AWGM-BYPASS6 вместе с черновиком. Идемпотентно.
// Вызывать только после снятия правил ip6tables, ссылающихся на набор, —
// иначе ipset ответит «set is in use by a kernel component».
func DestroySet6(ctx context.Context) error {
	err := DestroyNamedSet(ctx, SetName6)
	if serr := DestroyNamedSet(ctx, StagingSetName6); err == nil {
		err = serr
	}
	return err
}

// NormalizeEntry6 канонизирует IPv6-адрес или CIDR для ipset. Для всего
// остального (включая IPv4 и адреса с зоной) возвращает "".
func NormalizeEntry6(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if _, ipnet, err := net.ParseCIDR(raw); err == nil {
		if ipnet.IP.To4() != nil {
			return ""
		}
		return ipnet.String()
	}
	if ip := net.ParseIP(raw); ip != nil && ip.To4() == nil {
		return ip.String() + "/128"
	}
	return ""
}

// staging6 — IPv6-половина одного прохода Populate: записи копятся чанком и
// уходят в черновик AWGM-BYPASS6-STG по мере набора, commit меняет черновик
// с живым набором. Первая ошибка запоминается, и половина дальше молчит:
// живой набор при этом остаётся прежним (swap не состоялся).
type staging6 struct {
	enabled bool
	chunk   []string
	err     error
}

// newStaging6 готовит живой набор и пустой черновик. enabled=false —
// половина выключена: add и commit ничего не делают.
func newStaging6(ctx context.Context, enabled bool) *staging6 {
	s := &staging6{enabled: enabled}
	if !enabled {
		return s
	}
	if err := createNamedSetFamily(ctx, SetName6, familyInet6); err != nil {
		s.err = fmt.Errorf("create live set: %w", err)
		return s
	}
	if err := flushNamedSetFamily(ctx, StagingSetName6, familyInet6); err != nil {
		s.err = fmt.Errorf("flush staging: %w", err)
	}
	return s
}

// add кладёт строку .dat в чанк, если это IPv6-адрес или CIDR, и сбрасывает
// полный чанк в черновик.
func (s *staging6) add(ctx context.Context, raw string) {
	if !s.enabled || s.err != nil {
		return
	}
	c := NormalizeEntry6(raw)
	if c == "" {
		return
	}
	s.chunk = append(s.chunk, c)
	if len(s.chunk) >= IpsetChunkSize {
		s.flush(ctx)
	}
}

func (s *staging6) flush(ctx context.Context) {
	if len(s.chunk) == 0 || s.err != nil {
		return
	}
	if err := chunkedAddToSetWith(ctx, StagingSetName6, s.chunk, NormalizeEntry6); err != nil {
		s.err = fmt.Errorf("populate staging: %w", err)
	}
	s.chunk = s.chunk[:0]
}

// commit досыпает остаток, меняет черновик с живым набором и пишет дамп для
// v6-хука. Возвращает размер живого набора. Ошибка после swap («ipset save»)
// значит «набор живой, но дампа для хука нет» — счётчик при ней достоверен.
func (s *staging6) commit(ctx context.Context, savePath string) (n int, ok bool, err error) {
	if !s.enabled {
		return 0, false, nil
	}
	s.flush(ctx)
	if s.err != nil {
		// Недолитый черновик не оставляем: память он держит до следующего
		// прохода.
		_ = flushNamedSetFamily(ctx, StagingSetName6, familyInet6)
		return 0, false, s.err
	}
	bin, err := ipsetBin()
	if err != nil {
		return 0, false, err
	}
	res, err := runIpsetCtl(ctx, bin, "swap", SetName6, StagingSetName6)
	if err != nil {
		return 0, false, sysexec.FormatError(res, fmt.Errorf("ipset swap: %w", err))
	}
	_ = flushNamedSetFamily(ctx, StagingSetName6, familyInet6)
	n, ok = entryCountCheckedOf(ctx, SetName6)
	if savePath != "" {
		if err := writeSaveFileOf(ctx, SetName6, savePath); err != nil {
			return n, ok, fmt.Errorf("ipset save: %w", err)
		}
	}
	return n, ok, nil
}
