package router

import (
	"context"
	"strings"
	"testing"
)

// Удаление пакета обязано снимать перехват из ядра (F623): иначе джампы в
// TPROXY/REDIRECT ведут на порты остановленного sing-box. Набор обхода —
// только ПОСЛЕ правил: пока в ядре стоит `--match-set`, ipset его не снесёт.
//
// Вызов и его место в cmd/awg-manager/cleanup.go сторожит
// TestRunCleanup_ReleasesNetfilterBeforeCleanupAll.
func TestReleaseNetfilterForRemoval_UninstallsThenDropsBypassSet(t *testing.T) {
	fe := newFakeExec()
	callsAtTeardown := -1
	orig := removalTeardownBypassSet
	removalTeardownBypassSet = func(*ServiceImpl, context.Context) { callsAtTeardown = len(fe.calls) }
	t.Cleanup(func() { removalTeardownBypassSet = orig })

	ReleaseNetfilterForRemoval(context.Background(), Deps{IPTables: newFakeIPTables(fe)})

	lastFlush := -1
	for i, c := range fe.calls {
		if c.kind == "iptables" && strings.Join(c.args, " ") == "-t mangle -F "+ChainName {
			lastFlush = i
		}
	}
	if lastFlush < 0 {
		t.Fatalf("цепочка %s не снята, вызовы: %v", ChainName, fe.calls)
	}
	if callsAtTeardown <= lastFlush {
		t.Errorf("набор обхода снесён до снятия правил или не снесён (teardown после %d вызовов, flush — вызов %d)", callsAtTeardown, lastFlush)
	}
}
