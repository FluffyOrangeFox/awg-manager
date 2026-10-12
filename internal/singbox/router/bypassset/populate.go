package bypassset

import (
	"context"
	"fmt"

	"github.com/hoaxisr/awg-manager/internal/storage"
	sysexec "github.com/hoaxisr/awg-manager/internal/sys/exec"
)

// GeoSource отдаёт строки geoip-тега из .dat-файлов.
type GeoSource interface {
	// GeoIPTagLines возвращает строки тега (bare IP/CIDR/IPv6 из .dat).
	// notFound=true — тега нет ни в одном файле (не ошибка наполнения).
	GeoIPTagLines(tag string) (lines []string, notFound bool, err error)
}

// PopulateInput — что класть в набор и куда сохранять дамп.
type PopulateInput struct {
	GeoIPTags []string
	SavePath  string // "" — save-файл не писать (тесты)
	// V6 — наполнять и IPv6-близнеца (AWGM-BYPASS6) IPv6-записями тех же
	// тегов. false — IPv6-записи .dat пропускаются, как и раньше; сам набор
	// при этом не трогается: его сносит v6-слой роутера.
	V6 bool
	// SavePath6 — дамп AWGM-BYPASS6 для v6-хука. "" — не писать.
	SavePath6 string
}

// PopulateResult — итог наполнения: размер живого набора (CountOK=false —
// счётчик получить не удалось, ноль недостоверен) и теги, которых нет в .dat.
type PopulateResult struct {
	EntryCount  int
	CountOK     bool
	MissingTags []string

	// Итог IPv6-половины (AWGM-BYPASS6); заполняется только при V6. Отдельно
	// от полей выше намеренно: половины независимы — у каждой свой черновик и
	// свой swap, — и отказ одной не должен выглядеть как сбой всего набора.
	EntryCount6 int
	Count6OK    bool
	// Err6 — отказ IPv6-половины. Ошибкой Populate он НЕ становится:
	// IPv4-набор при этом собран, сохранён и действует.
	Err6 error
}

// Populate статично наполняет AWGM-BYPASS: geoip-теги → staging → атомарный
// swap → ipset save в SavePath. Никакого DNS и сети. Ошибка до swap
// оставляет живой набор нетронутым.
func Populate(ctx context.Context, geo GeoSource, in PopulateInput) (PopulateResult, error) {
	var res PopulateResult
	if err := CreateSet(ctx); err != nil {
		return res, fmt.Errorf("create live set: %w", err)
	}
	if err := EnsureStagingSet(ctx); err != nil {
		return res, fmt.Errorf("create staging: %w", err)
	}
	if err := FlushStagingSet(ctx); err != nil {
		return res, fmt.Errorf("flush staging: %w", err)
	}
	var chunk []string
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		err := ChunkedAddStaging(ctx, chunk)
		chunk = chunk[:0]
		return err
	}
	// IPv6-записи идут в свой черновик теми же чанками, что и IPv4: копить
	// семейство целиком — это вся IPv6-часть выбранных тегов в куче разом, а
	// наполнение идёт на роутерах с 128–256 МБ памяти. После первого отказа
	// половина выключается до конца прохода (v6.err), IPv4 идёт дальше.
	v6 := newStaging6(ctx, in.V6)
	for _, tag := range in.GeoIPTags {
		lines, notFound, err := geo.GeoIPTagLines(tag)
		if notFound {
			res.MissingTags = append(res.MissingTags, tag)
			continue
		}
		if err != nil {
			return res, fmt.Errorf("geoip tag %q: %w", tag, err)
		}
		for _, l := range lines {
			if c := NormalizeEntry(l); c != "" {
				chunk = append(chunk, c)
				if len(chunk) >= IpsetChunkSize {
					if err := flush(); err != nil {
						return res, fmt.Errorf("populate staging: %w", err)
					}
				}
				continue
			}
			v6.add(ctx, l)
		}
	}
	if err := flush(); err != nil {
		return res, fmt.Errorf("populate staging: %w", err)
	}
	if err := SwapWithStaging(ctx); err != nil {
		return res, fmt.Errorf("swap: %w", err)
	}
	_ = FlushStagingSet(ctx)
	res.EntryCount, res.CountOK = EntryCountChecked(ctx)
	if in.SavePath != "" {
		if err := writeSaveFile(ctx, in.SavePath); err != nil {
			// swap состоялся — набор живой; но без save-файла хук после
			// ребута останется без источника восстановления: ошибку отдаём.
			return res, fmt.Errorf("ipset save: %w", err)
		}
	}
	if in.V6 {
		res.EntryCount6, res.Count6OK, res.Err6 = v6.commit(ctx, in.SavePath6)
	}
	return res, nil
}

// writeSaveFile кладёт дамп живого набора в path — источник восстановления
// набора после перезагрузки роутера.
func writeSaveFile(ctx context.Context, path string) error {
	return writeSaveFileOf(ctx, SetName, path)
}

func writeSaveFileOf(ctx context.Context, name, path string) error {
	bin, err := ipsetBin()
	if err != nil {
		return err
	}
	r, err := runIpsetCtl(ctx, bin, "save", name)
	if err != nil {
		return sysexec.FormatError(r, err)
	}
	return storage.AtomicWritePerm(path, []byte(r.Stdout), 0644)
}
