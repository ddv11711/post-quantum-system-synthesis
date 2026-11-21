# Переносимый типизированный граф

`component-security-graph/v1` — самостоятельный вход ядра. Произвольные строковые ID,
Unicode, имена людей, серверов и устройств разрешены. Названия объектов и номера
не определяют права, типы безопасности или нормативные требования. Схема находится
в `schemas/portable_graph.schema.json`; компилятор — `analyzer.portable.load_portable`.

Вход сохраняется в `portable_source`, исходные связи — в `source_graph`. Для фактов,
политик, узлов и переходов сохраняются источник, JSON-путь, состояние, исходное
значение и способ преобразования. Переданный Python-объект не изменяется.

## Минимальный пример

```json
{
  "schema": "component-security-graph/v1",
  "state": "before",
  "nodes": {
    "guest": {"type": "subject"},
    "archive": {"type": "data"}
  },
  "edges": [{
    "id": "open-interface", "type": "access",
    "source": "guest", "target": "archive", "subject": "guest",
    "operations": ["read"], "allowed": true, "enabled": true
  }],
  "policy": {
    "denies": [{"subject": "guest", "object": "archive", "operations": ["read"]}]
  }
}
```

Результат — FAIL: фактический переход разрешает запрещенное политикой чтение.
Политика не удаляет этот переход перед анализом. Если убрать `allowed` или
`enabled`, получится UNKNOWN. Если заменить `access` на `untyped`, связь останется
структурной и не докажет чтение.

`nodes` также может быть списком записей с `id` (или `key`). ID уникальны.
Канонические типы: `component`, `subject`, `data`, `function`, `event`, `key`,
`role`, `channel`, `change`, `unknown`. Допустимые явные синонимы:

| Входной тип | Канонический тип |
|---|---|
| user, account | subject |
| file, database, storage | data |
| host, server, firewall, antivirus, service | component |

Исходный тип сохраняется. Синоним `firewall` сам по себе не доказывает покрытие
какого-либо объекта. Для покрытия нужна отдельная типизированная связь.

## Фактические данные и неизвестность

Для трёх уровней взаимодействия используйте `type: "interaction"`, `layers` и при необходимости `bidirectional`, `protection_via`. Привязка `channel` в ребре доступа или переноса включает F∧L∧S в условия этого перехода. Формат и пример: [контракт FLS](fls_graph.md). `node.cluster` задаёт вкладку кластера; при отсутствии используются `pc`, затем `group`, затем общие ресурсы. В Excel уровни редактируются отдельными столбцами `physical`, `syntactic`, `semantic`, а группа узла — столбцом `cluster`.

Перечисление узла означает `present=TRUE`, если явно не задано иное. Остальные
свойства не получают положительных значений по умолчанию: `enabled`, `healthy`,
`transport_enabled`, `integrity`, `trusted_boot`, `readable`, `key_accessible`,
`event_possible` принимаются только из явных полей. Значения — true, false или
`"UNKNOWN"`; отсутствие также неизвестно.

Каждая access/flow/copy-связь получает отдельный атом `transition_enabled`:
конъюнкцию ее `allowed` и `enabled`. Поэтому закрытый интерфейс не противоречит
другому открытому интерфейсу того же объекта. Неизвестный тип исходного ребра не
становится access. `conditions` — дополнительные типизированные атомы
`{"predicate": "available", "args": ["router"]}`. Для access необходимо явно
указать `subject` и `operations`. Контекст субъекта, операции и `scenario`
сохраняется на всем пути. `via` обозначает компонент, присутствие которого
необходимо переходу; работоспособность задается отдельным условием `available`
или `transport`, когда такая семантика действительно известна.

Глобальная фактическая ACL задается отдельно:

```json
{"actual_acl": [
  {"subject": "guest", "object": "archive", "operations": ["read"], "allowed": false}
]}
```

Чтобы переход зависел от этой ACL, в его записи требуется `use_acl: true`.
Отсутствующая ACL остается UNKNOWN. Ни grants политики, ни метки безопасности
не переписывают фактические разрешения.

| Тип связи | Направление и значение |
|---|---|
| dependency | source зависит от target; `mode: all` или `any` |
| protection, control_coverage | механизм source покрывает target функцией `control` |
| authentication | механизм source покрывает target функцией аутентификации |
| logger | регистратор source покрывает событие target |
| backup | данные source имеют копию target |
| key_required | копия source требует ключ target |
| flow, copy | перенос source → target субъектом subject; операция write |
| physical, channel, stores, executes, owns, authenticates, independent | одноименные типизированные факты; сами по себе не дают доступ |
| untyped | только структурная связь |

Связи-факты имеют `value`, по умолчанию TRUE: сам факт указанного отношения
явно объявлен записью. Для access/flow/copy это не заменяет обязательные
условия `allowed` и `enabled`. Отсутствующий ID ребра вычисляется из его
содержимого; для адресуемых исправлений удобнее задать устойчивый ID явно.

`node.dependencies: {"all": [...], "any": [...]}` задает полное выражение
зависимостей; `{"all": []}` — явно подтвержденное отсутствие обязательных
зависимостей. Перечень dependency-ребер полон только при
`node.dependencies_complete: true`. Иначе известные зависимости сохраняются,
но неизвестные дополнительные условия не позволяют доказать работоспособность.
Известный отказ обязательной зависимости все равно дает FALSE.

Полнота других отношений задается точной областью:

```json
{"completeness": [
  {"predicate": "transitions", "args_prefix": ["guest", "read", "default", "access"], "complete": true},
  {"predicate": "cover", "args_prefix": ["archive", "filter"], "complete": true},
  {"predicate": "key_required", "args_prefix": ["backup-copy"], "complete": true}
]}
```

Конечный список ребер сам по себе не означает закрытого мира.

## Политика и автоматически создаваемые требования

`policy.grants` — разрешенные операции, `policy.denies` — запрещенные,
`policy.required` — обязательные. Запись содержит `subject` **либо** `role`,
`object`, список `operations`, необязательные `scenario` и `kind`.
Роли раскрываются через явно объявленные `node.roles`; `roles_complete: true`
закрывает перечень ролей конкретного субъекта. Неподтвержденное членство остается
UNKNOWN и не превращается ни в действующее разрешение, ни в доказанный запрет.

`policy.default: "deny"` раскрывается в запреты только при `policy.complete: true`.
Это полнота списка разрешений **политики**, а не полнота фактических переходов.
Область ограничивается `policy.scope.subjects/objects/operations/scenario`.
Без scope используются объявленные субъекты, все узлы, кроме субъектов/ролей, плюс явные
цели access-ребер (включая учетные записи и роли), и четыре операции. Если полный default-deny используется совместно с обязательной
операцией, она должна быть разрешена в grants; противоречивая политика дает
MODEL_ERROR. `default: "unknown"` ничего не запрещает по отсутствию записи.

Явные намерения узла создают проверяемые требования:

| Поле узла | Проверка |
|---|---|
| required: true | required_function |
| required_controls: [имена функций] | protection |
| authentication_required: true | authentication |
| logging_required: true (event) | logging |
| backup_required: true (data) | recovery |
| crypto_required: true (channel) | crypto |
| redundancy_required: true, replicas, replicas_complete | redundancy |
| expected_parameters: {имя: значение} | configuration относительно фактических parameters |
| integrity_required / trusted_boot_required: true | configuration относительно соответствующего факта |
| known_vulnerabilities: [{id, patched}] | configuration: parameter `patch:<id>` должен быть TRUE |

Флаги намерений и полноты принимают только JSON true/false: строка `"TRUE"`
в поле `required` или `use_acl` отклоняется, а не игнорируется. Трехзначные поля
фактов (`present`, `allowed` и т. п.) отдельно поддерживают строки TRUE/FALSE/UNKNOWN.

Вход с явно указанной schema также поддерживает канонические списки `facts` и
`requirements` для всех классов проверок ядра: роли, согласование изменений,
криптография, документные свидетельства и другие. Они сохраняют ID и исходное
provenance, дополняются ссылкой на JSON-путь, не отбрасываются и учитываются
в лимите 10 000 требований. Синтаксис записей проверяется компилятором,
типовая и логическая согласованность — публичным анализатором (MODEL_ERROR).
Неподдержанный checker получает NOT_CHECKED.

Уязвимость должна быть явно известна из входа. Название продукта не запускает
внешний поиск CVE и не доказывает уязвимость. Типы без намерений не создают
вымышленных нормативных требований. Если проверять нечего, отдельная проверка
`semantic_readiness` возвращает UNKNOWN с причиной, вместо пустого безопасного
отчета. Число автоматически созданных требований ограничено 10 000; превышение
диагностируется, требования не отбрасываются молча.

## Метки конфиденциальности и целостности

Узлы используют `security_label`, `integrity_label`, субъекты дополнительно
`clearance`: `{"level": "restricted", "categories": ["research"]}`.
Уровни перечисляются от низкого к высокому в
`security_policy.confidentiality_levels` и `integrity_levels`.
Профиль включается через `security_policy.enabled: true`; целостность — отдельно
`integrity_enabled: true`. Имена уровней и категорий произвольные.
Отсутствующий уровень или список категорий — UNKNOWN, `categories: []` —
известное отсутствие категорий.

Для явно включенного профиля создаются `mandatory_access` для каждого
объявленного субъекта, узла данных, объекта с явной меткой или цели access-ребра
и обеих операций read/write даже при отсутствии
access-ребер. Метки субъектов сами по себе не делают их объектами проверки;
субъект становится объектом при явном access-ребре к нему. Область можно явно сузить через `security_policy.scope` с полями
`subjects`, `objects`, `operations`, `scenarios`; без нее проверяется также каждый
объявленный контекст access. Создаются `label_flow` для каждого прямого flow/copy-ребра,
`clearance` для явно указанного допуска. Анализ сохраняет реальные пути:
запрет по меткам не удаляет опасный фактический переход. Поток к более низкой
метке проверяется также на промежуточных участках цепи копирования.
`label_flow` связан с каталогом как формальный фрагмент FT025; это не
утверждение о полном выполнении пункта каталога или нормативного профиля.

Деклассификация допустима лишь как точная запись
`security_policy.declassifications` с `id`, `subject`, `source`, `target`,
`operation: "write"`, `scenario`, `from_label`, `to_label`,
`authorized: "TRUE"`, `provenance`. Она не создает ACL, не дает произвольных
полномочий и не отменяет требования целостности. Формальная семантика доминирования
и применимости находится в реализации `analyzer/mandatory.py` и общих документах модели.

## Исправления только в разрешенной области

```json
{"repair_policy": {"allowed_operations": [
  {"operation": "revoke_access", "edges": ["open-interface"], "cost": 1},
  {"operation": "enable_control", "nodes": ["guard", "logger"], "cost": 1},
  {"operation": "restore_component", "nodes": ["failed-host"], "cost": 1}
]}}
```

Компилятор сохраняет эту политику. `attach_repair_catalog` создает конечный каталог
действий, точную область mutable и предусловия. Неизвестные факты не становятся
произвольно известными. Для глобальной ACL разрешение задается точными тройками
в `acl: [{subject, object, operation}]`. Локальные запреты на отдельные интерфейсы
используют `edges`. Требования, уровни, метки и свидетельства этим каталогом
не редактируются.

Для расширенных сценариев вход также может содержать канонические `mutable`
и `action_catalog`: точные атомы и действия с effects, preconditions, targets,
requires/excludes и cost. Компилятор сохраняет их; публичный анализатор и
оптимизатор проверяют типы и допустимость эффектов. При наличии `repair_policy`
вызов `attach_repair_catalog` заменяет каталог действиями разрешенной области.

## Воспроизводимый пример

Из корня репозитория:

```bash
.venv-analyzer/bin/python - <<'PY'
import json
from pathlib import Path
from analyzer.portable import load_portable
from analyzer.engine import analyze
from analyzer.remediation import attach_repair_catalog
from analyzer.repairs import find_repairs
path = Path('examples/portable/mixed_security.json')
payload = json.loads(path.read_text())
model = load_portable(payload, source=str(path))
print('before:', analyze(model)['summary'])
model = attach_repair_catalog(model, payload['repair_policy'])
repair = find_repairs(model)
print(repair['status'], repair['objective_value'])
print('after:', repair['verification']['summary'])
PY
.venv-analyzer/bin/python -m pytest -q tests/test_portable.py
```

Для `mixed_security.json` подтверждено: до исправления **FAIL=5, PASS=4**;
минимум в разрешенном каталоге **5 действий стоимостью 5**; после **PASS=9**.
Закрываются оба обходных интерфейса и опасная копия, включаются защитная функция
и регистратор. Это явно объявленная учебная конфигурация с произвольными ID,
а не заключение о приложенных ранее ПК.

`labels_unknown.json` демонстрирует UNKNOWN из-за неизвестных категорий субъекта.
`structural_only.json` демонстрирует UNKNOWN готовности семантики. Тесты проверяют
переименование ID, перестановку записей, независимые параллельные интерфейсы,
сохранение исходного payload, неполноту ролей/зависимостей, политику закрытого мира,
недоступный ключ восстановления и повторную проверку исправления.
