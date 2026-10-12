package bypassset

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeEntry6(t *testing.T) {
	cases := map[string]string{
		"2001:db8::/32":      "2001:db8::/32",
		"2001:db8::1/32":     "2001:db8::/32", // биты хоста маскируются
		"2001:DB8::1":        "2001:db8::1/128",
		"  2a00::/12  ":      "2a00::/12",
		"1.2.3.0/24":         "", // IPv4 — не сюда
		"5.5.5.5":            "",
		"fe80::1%br0":        "", // адрес с зоной в набор не кладётся
		"2001:db8::/129":     "",
		"not-an-ip":          "",
		"":                   "",
		"::ffff:1.2.3.4":     "", // IPv4-mapped — это IPv4
		"::ffff:1.2.3.0/120": "",
	}
	for in, want := range cases {
		if got := NormalizeEntry6(in); got != want {
			t.Errorf("NormalizeEntry6(%q) = %q, want %q", in, got, want)
		}
	}
}

func hasPrefixLine(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

// При V6 IPv6-записи тех же тегов уходят в свой набор через свой черновик и
// свой swap, а дамп пишется в отдельный файл — по нему v6-хук возвращает набор
// после перезагрузки.
func TestPopulate_V6FillsOwnSet(t *testing.T) {
	tr := installIPSetStub(t)
	geo := stubGeo{lines: map[string][]string{
		"ru": {"1.2.3.0/24", "2a00::/32", "5.5.5.5", "2001:db8::1"},
	}}
	save6 := filepath.Join(t.TempDir(), "bypass6.ipset")

	res, err := Populate(context.Background(), geo, PopulateInput{
		GeoIPTags: []string{"ru"},
		V6:        true,
		SavePath6: save6,
	})
	if err != nil {
		t.Fatalf("Populate: %v", err)
	}
	// Стаб отвечает «2 записи» на каждый набор; у половин свои счётчики.
	if res.EntryCount != 2 || !res.CountOK {
		t.Errorf("EntryCount/CountOK: want 2/true, got %d/%v", res.EntryCount, res.CountOK)
	}
	if res.EntryCount6 != 2 || !res.Count6OK || res.Err6 != nil {
		t.Errorf("EntryCount6/Count6OK/Err6: want 2/true/nil, got %d/%v/%v", res.EntryCount6, res.Count6OK, res.Err6)
	}

	argv := tr.argv()
	if !hasPrefixLine(argv, "create "+SetName6+" hash:net maxelem 262144 family inet6") {
		t.Errorf("набор IPv6 обязан создаваться в семействе inet6: %v", argv)
	}
	swap4, swap6 := -1, -1
	for i, a := range argv {
		switch a {
		case "swap " + SetName + " " + StagingSetName:
			swap4 = i
		case "swap " + SetName6 + " " + StagingSetName6:
			swap6 = i
		}
	}
	if swap4 < 0 || swap6 < 0 || swap6 < swap4 {
		t.Errorf("оба набора обязаны пройти swap, IPv4 первым: swap4=%d swap6=%d\n%v", swap4, swap6, argv)
	}

	want := []string{
		"add " + StagingSetName + " 1.2.3.0/24",
		"add " + StagingSetName + " 5.5.5.5/32",
		"add " + StagingSetName6 + " 2a00::/32",
		"add " + StagingSetName6 + " 2001:db8::1/128",
	}
	if got := tr.stdin(); !equalSeq(got, want) {
		t.Errorf("restore input:\nwant %v\ngot  %v", want, got)
	}
	if _, err := os.Stat(save6); err != nil {
		t.Errorf("дамп IPv6-набора не записан: %v", err)
	}
}

// Без V6 IPv6-набор не трогается вовсе: им владеет v6-слой роутера, и
// наполнение при выключенном перехвате IPv6 не должно ни создавать его, ни
// сносить.
func TestPopulate_WithoutV6_LeavesV6SetAlone(t *testing.T) {
	tr := installIPSetStub(t)
	geo := stubGeo{lines: map[string][]string{"ru": {"1.2.3.0/24", "2a00::/32"}}}

	if _, err := Populate(context.Background(), geo, PopulateInput{GeoIPTags: []string{"ru"}}); err != nil {
		t.Fatalf("Populate: %v", err)
	}
	for _, a := range tr.argv() {
		if strings.Contains(a, SetName6) {
			t.Errorf("без V6 набор IPv6 трогать нельзя: %q", a)
		}
	}
}

func TestDestroySet6_RemovesLiveAndStaging(t *testing.T) {
	tr := installIPSetStub(t)
	if err := DestroySet6(context.Background()); err != nil {
		t.Fatalf("DestroySet6: %v", err)
	}
	want := []string{"destroy " + SetName6, "destroy " + StagingSetName6}
	if got := tr.argv(); !equalSeq(got, want) {
		t.Errorf("вызовы: want %v, got %v", want, got)
	}
}

// IPv6-записи уходят в черновик чанками по мере чтения тегов, как и IPv4, а не
// копятся целиком до конца прохода: вся IPv6-часть выбранных тегов в куче
// разом — заметная нагрузка на роутерах с малой памятью.
func TestPopulate_V6StreamsInChunks(t *testing.T) {
	tr := installIPSetStub(t)
	const n6 = IpsetChunkSize*2 + 10
	lines := make([]string, 0, n6+1)
	lines = append(lines, "1.2.3.0/24")
	for i := 0; i < n6; i++ {
		lines = append(lines, fmt.Sprintf("2001:db8:%x::/48", i))
	}
	geo := stubGeo{lines: map[string][]string{"ru": lines}}

	if _, err := Populate(context.Background(), geo, PopulateInput{GeoIPTags: []string{"ru"}, V6: true}); err != nil {
		t.Fatalf("Populate: %v", err)
	}

	argv := tr.argv()
	swap4, restores, restoresBeforeSwap4 := -1, 0, 0
	for i, a := range argv {
		switch a {
		case "swap " + SetName + " " + StagingSetName:
			swap4 = i
		case "restore -exist":
			restores++
			if swap4 < 0 {
				restoresBeforeSwap4++
			}
		}
	}
	// Два полных чанка IPv6 + остаток + один чанк IPv4.
	if restores != 4 {
		t.Errorf("вызовов ipset restore: %d, want 4 (2 полных чанка IPv6, остаток, чанк IPv4)\n%v", restores, argv)
	}
	// Полные чанки IPv6 сброшены ещё во время чтения тега — до того, как
	// IPv4-набор дошёл до swap. Копи мы семейство целиком, до swap был бы один
	// restore (IPv4).
	if swap4 < 0 || restoresBeforeSwap4 != 3 {
		t.Errorf("до swap IPv4-набора ожидалось 3 restore (2 чанка IPv6 + IPv4), got %d\n%v", restoresBeforeSwap4, argv)
	}
	added6 := 0
	for _, l := range tr.stdin() {
		if strings.HasPrefix(l, "add "+StagingSetName6+" ") {
			added6++
		}
	}
	if added6 != n6 {
		t.Errorf("в черновик IPv6 ушло %d записей, want %d", added6, n6)
	}
}

// installIPSetStubFailing6 — как installIPSetStub, но `ipset restore` падает,
// если во входе есть записи черновика IPv6.
func installIPSetStubFailing6(t *testing.T) *ipsetTrace {
	t.Helper()
	log := filepath.Join(t.TempDir(), "calls.log")
	script := fmt.Sprintf(`#!/bin/sh
LOG=%q
echo "ARGV: $*" >> "$LOG"
case "$1" in
restore)
	rc=0
	while IFS= read -r line; do
		echo "STDIN: $line" >> "$LOG"
		case "$line" in *%s*) rc=1 ;; esac
	done
	exit $rc
	;;
save)
	echo "create AWGM-BYPASS hash:net family inet maxelem 262144"
	echo "add AWGM-BYPASS 1.2.3.0/24"
	;;
list)
	if [ "$3" = "-t" ]; then
		echo "Name: AWGM-BYPASS"
		echo "Number of entries: 2"
	fi
	;;
esac
exit 0
`, log, StagingSetName6)
	bin := writeStubIPSet(t, script)
	withHealthTestEnv(t, []string{bin}, func(string) (bool, string) { return false, "" })
	return &ipsetTrace{t: t, log: log}
}

// Отказ IPv6-половины не роняет наполнение: IPv4-набор собран, прошёл swap и
// сохранён, ошибка Populate пуста, а причина лежит в Err6. Живой IPv6-набор
// при этом не тронут — до swap дело не дошло.
func TestPopulate_V6FailureLeavesV4Built(t *testing.T) {
	tr := installIPSetStubFailing6(t)
	geo := stubGeo{lines: map[string][]string{
		"ru": {"1.2.3.0/24", "2a00::/32", "5.5.5.5"},
	}}
	dir := t.TempDir()
	save4, save6 := filepath.Join(dir, "bypass.ipset"), filepath.Join(dir, "bypass6.ipset")

	res, err := Populate(context.Background(), geo, PopulateInput{
		GeoIPTags: []string{"ru"},
		SavePath:  save4,
		V6:        true,
		SavePath6: save6,
	})
	if err != nil {
		t.Fatalf("отказ IPv6-половины не должен быть ошибкой Populate: %v", err)
	}
	if res.EntryCount != 2 || !res.CountOK {
		t.Errorf("IPv4-набор обязан быть собран: %d/%v", res.EntryCount, res.CountOK)
	}
	if res.Err6 == nil || !strings.Contains(res.Err6.Error(), "populate staging") {
		t.Fatalf("Err6 обязан назвать причину отказа IPv6-половины, got %v", res.Err6)
	}
	if res.Count6OK || res.EntryCount6 != 0 {
		t.Errorf("размер несобранного IPv6-набора — не факт: %d/%v", res.EntryCount6, res.Count6OK)
	}
	sawSwap4 := false
	for _, a := range tr.argv() {
		if a == "swap "+SetName+" "+StagingSetName {
			sawSwap4 = true
		}
		if a == "swap "+SetName6+" "+StagingSetName6 {
			t.Errorf("недолитый черновик IPv6 не должен дойти до swap")
		}
	}
	if !sawSwap4 {
		t.Error("IPv4-набор обязан пройти swap")
	}
	if _, err := os.Stat(save4); err != nil {
		t.Errorf("дамп IPv4-набора обязан быть записан: %v", err)
	}
	if _, err := os.Stat(save6); err == nil {
		t.Error("дамп несобранного IPv6-набора писать нельзя")
	}
}
