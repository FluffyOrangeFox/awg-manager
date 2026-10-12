package router

import (
	"context"

	"github.com/hoaxisr/awg-manager/internal/logging"
)

// ReleaseNetfilterForRemoval снимает перехват sb-router из ядра при удалении
// пакета (`opkg remove` → `--cleanup`), F623. Без него в режиме TPROXY в ядре
// оставались джампы PREROUTING в TPROXY/REDIRECT на порты, которые после
// остановки sing-box никто не слушает, плюс `ip rule` таблицы 100 и набор
// обхода: у устройств политики пропадал интернет до перезагрузки роутера.
// prerm снимает только файлы хуков, а сами правила в ядре — нет.
//
// Безусловно, без гейта по режиму: каждый шаг Uninstall идемпотентен, а в
// policy-tun в той же цепочке живут классы QoS (Install DSCPOnly). Тот же
// порядок, что в disable: набор — только после снятия правил с `--match-set`.
//
// ServiceImpl собирается мимо NewService по той же причине, что в
// ReleasePolicyTunForRemoval: тот переписывает netfilter-хук на диске.
func ReleaseNetfilterForRemoval(ctx context.Context, d Deps) {
	if d.IPTables == nil {
		d.IPTables = NewIPTables()
	}
	s := &ServiceImpl{
		deps:      d,
		bypassLog: logging.NewScopedLogger(d.AppLog, logging.GroupRouting, logging.SubBypassSet),
	}
	s.deps.IPTables.Uninstall(ctx)
	removalTeardownBypassSet(s, ctx)
}

// removalTeardownBypassSet — шов теста: без него тест экспортируемой функции
// звал бы ipset хоста.
var removalTeardownBypassSet = (*ServiceImpl).teardownBypassSet
