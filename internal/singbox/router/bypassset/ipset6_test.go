package bypassset

import (
	"context"
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
	// Стаб отвечает «2 записи» на каждый набор: сумма по обоим.
	if res.EntryCount != 4 || !res.CountOK {
		t.Errorf("EntryCount/CountOK: want 4/true, got %d/%v", res.EntryCount, res.CountOK)
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
