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

// populate6 переливает уже отобранные IPv6-записи в AWGM-BYPASS6 через
// черновик и атомарный swap. Возвращает размер живого набора.
func populate6(ctx context.Context, entries []string, savePath string) (n int, ok bool, err error) {
	bin, err := ipsetBin()
	if err != nil {
		return 0, false, err
	}
	if err := createNamedSetFamily(ctx, SetName6, familyInet6); err != nil {
		return 0, false, fmt.Errorf("create live set: %w", err)
	}
	if err := flushNamedSetFamily(ctx, StagingSetName6, familyInet6); err != nil {
		return 0, false, fmt.Errorf("flush staging: %w", err)
	}
	if err := chunkedAddToSetWith(ctx, StagingSetName6, entries, NormalizeEntry6); err != nil {
		return 0, false, fmt.Errorf("populate staging: %w", err)
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
