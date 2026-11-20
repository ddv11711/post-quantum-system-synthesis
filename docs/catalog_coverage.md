# Покрытие исходного каталога

Проверен приложенный DOCX: **324 уникальных пункта, 47 разделов, версия 1.0 от 18.11.2026**. Извлечены все 1474 параграфа, включая введение, приложения и ссылки на основания. Исходный файл не изменён. `data/catalogue_extracted.txt` — производная текстовая копия, `data/rule_registry.json` — реестр с исходными полями, ссылкой на параграф OOXML, SHA-256, датой нормативного снимка и формализацией.

В приложении описан прежний граф из 101 вершины и 556 связей; его ID не применяются к новой системе. В старом графе 83 — VPN, в новом HTML `1:83` — файл. Сопоставления основаны на смысле проверки и явно назначенных типах, а не номере старого компонента. Определения FLS/F/L/S в каталоге нет; оно не придумано и цвета не используются как типы безопасности.

## Как читать поддержку

`implemented` означает **исполняемый формальный фрагмент** пункта. У соответствующих записей явно указаны `implementation_scope=formal_fragment_only` и `whole_rule_implemented=false`: приведённый документ содержит дополнительные условия применимости, полноты и внешних свидетельств, которые нельзя подтвердить одной технической проверкой. Это не заявление о реализации всех нормативных требований. Формальное условие, входные факты, область полноты, checker, объяснение, шаблоны исправлений, тесты и непокрытый остаток перечислены для каждого сопоставления в JSON.

`requires_evidence` обозначает необходимость документа, испытания или внешнего подтверждения. `requires_additional_data` означает, что нужен предметный набор данных и дополнительная формализация за пределами уже сопоставленных фрагментов. `unsupported` означает отсутствие необходимой семантики или отдельного проверяющего модуля. Причина конкретного остатка приведена в каждой записи реестра, а не заменена фиктивным PASS.

## Применимость и результат

Импорт не включает одновременно банковский, государственный, АСУ, криптографический или квантовый профили. Каждый пункт начинает с применимости UNKNOWN. Перечни оснований и даты воспроизводятся из каталога; текущая юридическая актуальность источников здесь заново не утверждается.

`coverage(catalog, analysis, applicability)` возвращает строку для каждого rule_id. Требуется явное `applicability[rule_id] = TRUE/FALSE/UNKNOWN`; отсутствие значения — UNKNOWN, а не NOT_APPLICABLE. Частные результаты связываются полем `catalog_rule_ids`. Они видны в `evaluated_fragments`, даже когда полная применимость нормативного пункта не установлена.

Подтверждённое нарушение достаточного формального условия при TRUE-применимости даёт FAIL, несмотря на второстепенные UNKNOWN. PASS требует всех успешных связанных проверок и явного `catalog_scope=complete` у каждой: это утверждение составителя профиля о полном охвате исходного условия, которое следует обосновать. По умолчанию `catalog_scope=fragment`, поэтому успешный локальный пример не сертифицирует исходный нормативный пункт. Ошибка модели не даёт PASS. При UNKNOWN-применимости первичный статус остаётся UNKNOWN, а необходимость свидетельств сохраняется отдельным признаком.

## Границы проверяющих модулей

- Доступ вычисляется по типизированным переходам в постоянном контексте субъекта, операции и сценария; политика сравнивается с результатом и не фильтрует доступ.
- Защита и аутентификация проверяют действующие механизмы с явным покрытием и полнотой альтернатив. Отдельно объявленные обходные пути проверяются через `bypass_subject` и соответствующий контекст.
- Журналирование проверяет возможное событие, покрывающий регистратор и его зависимости. Самостоятельное измерение правильности записанных полей, сроков хранения и часов не производится.
- Резервирование и восстановление используют явно объявленные зависимости, независимость, доступность копии и ключа. Время восстановления и физическая пропускная способность не вычисляются из топологии.
- Проверка конфигурации сравнивает наблюдённое значение с принятым эталоном; она не сканирует прошивку, не ищет CVE и не выдаёт сертификаты.
- Криптографическая проверка использует конкретный участок, признак защиты, параметры и доступность сторон. Полнота инвентаризации всех участков должна быть задана профилем.
- Квантовый checker реализует только явно объявленную учебную модель пассивного раскрытия. Подделка подписи с переходом доверия (CR042), композиция гибридных алгоритмов (CR046) и раскрытие хранимых данных через ключ-обёртку (CR043) не поддержаны. Нормативная допустимость из сценарной устойчивости не выводится.
- Смена личности, получение новых ролей и безопасные последовательности промежуточных состояний не реализованы. Валидатор диагностирует такие запросы; оптимизатор поддерживает атомарные совместимые эффекты.

## Состав реестра

Количество сопоставленных пунктов не является числом независимых находок. Ни один из 324 пунктов не получает PASS только по факту импорта.

| Категория поддержки | Количество пунктов |
|---|---:|
| `implemented` | 194 |
| `requires_additional_data` | 40 |
| `requires_evidence` | 54 |
| `unsupported` | 36 |

| ID | Название | Поддержка | Проверяющие фрагменты |
|---|---|---|---|
| MD001 | Версия требований и дата проверяемого состояния | unsupported | — |
| MD002 | Однозначная идентификация компонентов | unsupported | — |
| MD003 | Определённый смысл каждого отношения | unsupported | — |
| MD004 | Полнота границ системы | unsupported | — |
| MD005 | Разделение требуемой политики и фактических настроек | unsupported | — |
| MD006 | Раздельный учёт операций и контекстов | unsupported | — |
| MD007 | Происхождение и актуальность фактов | requires_evidence | — |
| MD008 | Неизвестное значение не приравнивается к отрицательному | unsupported | — |
| MD009 | Подтверждённое отсутствие обязательного механизма | implemented | protection |
| MD010 | Различение типа компонента и его экземпляра | unsupported | — |
| MD011 | Смысл численных атрибутов | unsupported | — |
| MD012 | Полнота сведений о проверяемом требовании | requires_evidence | — |
| ST001 | Согласованность снимка конфигурации | unsupported | — |
| ST002 | Наличие не означает работоспособность и покрытие | implemented | required_function, protection |
| ST003 | Буквальное удаление компонента | unsupported | — |
| ST004 | Поведение защитного механизма при отказе | implemented | protection |
| ST005 | Альтернативный путь и обход контроля | implemented | authentication |
| ST006 | Обязательные и альтернативные зависимости | implemented | required_function |
| ST007 | Циклические зависимости | unsupported | — |
| ST008 | Независимость резервирования | implemented | redundancy |
| ST009 | Сохранение обязательств после удаления объекта | implemented | required_operation, required_function |
| ST010 | Действительность полномочий во времени | unsupported | — |
| ST011 | Смена субъекта и получение новых возможностей | unsupported | — |
| ST012 | Исполнимость последовательности действий | unsupported | — |
| CR001 | Область применения требований к персональным данным | requires_evidence | — |
| CR002 | Корректность категории обрабатываемых персональных данных | requires_evidence | — |
| CR003 | Категории и количество субъектов персональных данных | requires_evidence | — |
| CR004 | Обоснованность типа актуальных угроз | requires_evidence | — |
| CR005 | Согласованность установленного уровня защищённости | requires_additional_data | — |
| CR006 | Наследование требований между уровнями | requires_additional_data | — |
| FT001 | Обоснованность выбранного набора мер | requires_evidence | — |
| FT002 | Проверяемость компенсирующей меры | implemented | protection |
| FT003 | Функциональная пригодность средства защиты | implemented | protection |
| FT004 | Соответствие выбранного СЗИ условиям оценки соответствия | requires_evidence | — |
| FT005 | Периодическая оценка эффективности мер ИСПДн | requires_evidence | — |
| FT006 | Учет фактической конфигурации | requires_additional_data | — |
| FT007 | Полномочия на изменение конфигурации | implemented | forbidden_operation, authorized_change |
| FT008 | Согласование, оценка последствий и учет изменений | implemented | authorized_change |
| FT009 | Однозначная идентификация пользователя | requires_additional_data | — |
| FT010 | Отсутствие обхода обязательной аутентификации | implemented | authentication |
| FT011 | Аутентификация внешних пользователей | implemented | authentication |
| FT012 | Идентификация и аутентификация устройств | implemented | authentication |
| FT013 | Жизненный цикл идентификаторов и учетных записей | requires_additional_data | — |
| FT014 | Защита средств аутентификации | implemented | protection |
| FT015 | Реакция на утрату или компрометацию средства входа | requires_additional_data | — |
| FT016 | Защита аутентификационной информации при вводе и передаче | implemented | protection, crypto |
| FT017 | Ограничение неуспешных попыток входа | requires_additional_data | — |
| FT018 | Строгая аутентификация привилегированного доступа в ГИС | implemented | authentication |
| FT019 | Соответствие фактических операций эталонной политике | implemented | forbidden_operation |
| FT020 | Минимально необходимые привилегии | implemented | forbidden_operation |
| FT021 | Разделение несовместимых ролей | implemented | incompatible_roles |
| FT022 | Разграничение действий до аутентификации | implemented | forbidden_operation, authentication |
| FT023 | Ограничение параллельных сеансов | requires_additional_data | — |
| FT024 | Блокирование неактивного сеанса | requires_additional_data | — |
| FT025 | Сохранение меток и атрибутов безопасности | requires_additional_data | — |
| FT026 | Персонификация привилегированных записей, создающих другие записи | requires_additional_data | — |
| FT027 | Неиспользуемые привилегированные записи | requires_additional_data | — |
| FT028 | Встроенные привилегированные записи после настройки | requires_additional_data | — |
| FT029 | Регистрация привилегированных действий | implemented | logging |
| FT030 | Контроль обязательных предупреждений и уведомлений о входе | requires_additional_data | — |
| FT031 | Соответствие сетевых потоков утвержденной политике | implemented | forbidden_operation |
| FT032 | Отсутствие обхода обязательного контроля потока | implemented | protection |
| FT033 | Разделение сетевых сегментов | implemented | protection |
| FT034 | Контроль подключения внешней системы | implemented | protection |
| FT035 | Защита передачи за пределы контролируемой зоны | implemented | protection, crypto |
| FT036 | Защищенный путь управления средствами безопасности | implemented | protection, authentication, crypto |
| FT037 | Защита удаленного рабочего доступа | implemented | protection, authentication, crypto |
| FT038 | Личные устройства для удаленного рабочего доступа в ГИС | requires_evidence | — |
| FT039 | Территориальное условие сетей удаленного рабочего доступа в ГИС | requires_evidence | — |
| FT040 | Контроль беспроводных подключений | implemented | protection |
| FT041 | Идентификация, размещение и изоляция рабочих сетей Wi-Fi в ГИС | requires_additional_data | — |
| FT042 | Защита рабочих мобильных устройств | implemented | protection |
| FT043 | Подлинность сетевых соединений и разрешения имен | implemented | authentication, crypto |
| FT044 | Контроль периферии, мобильного кода, речи и видео | implemented | protection |
| FT045 | Разрешенный состав установленного ПО | implemented | configuration |
| FT046 | Разрешенный запуск программ и компонентов | implemented | forbidden_operation |
| FT047 | Управление временными и промежуточными файлами | requires_additional_data | — |
| FT048 | Выявление и применимость уязвимости | requires_additional_data | — |
| FT049 | Срок обработки критических и высоких уязвимостей в ГИС | requires_evidence | — |
| FT050 | Срок обработки остальных уязвимостей | requires_evidence | — |
| FT051 | Уведомление о ранее неизвестной ФСТЭК уязвимости | requires_evidence | — |
| FT052 | Доверенный источник и целостность обновления | implemented | configuration |
| FT053 | Тестирование обновления перед промышленной эксплуатацией | requires_evidence | — |
| FT054 | Разрешенная и контролируемая установка обновления | implemented | authorized_change |
| FT055 | Работоспособность и настройки средств защиты | implemented | required_function, protection, configuration |
| FT056 | Проверка правил учетных записей и паролей | implemented | configuration |
| FT057 | Покрытие объектов действующей антивирусной защитой | implemented | protection |
| FT058 | Обновление антивирусных признаков | implemented | configuration |
| FT059 | Антивирусная обработка почты, архивов и специальных файлов в АСУ | implemented | protection |
| FT060 | Охват действующей системой обнаружения вторжений | implemented | protection |
| FT061 | Актуальность правил обнаружения вторжений | implemented | configuration |
| FT062 | Доставка обнаружения до предусмотренной реакции | implemented | required_function |
| FT063 | Определение обязательных событий и сроков хранения | requires_evidence | — |
| FT064 | Полнота записи события | implemented | logging, configuration |
| FT065 | Сквозная работоспособность пути журналирования | implemented | logging |
| FT066 | Сохранение журнала в течение требуемого срока | implemented | configuration |
| FT067 | Реакция на сбои и переполнение журналирования | implemented | protection, logging |
| FT068 | Согласованность временных меток | implemented | configuration |
| FT069 | Защита журналов от неразрешенного чтения и изменения | implemented | forbidden_operation |
| FT070 | Контроль целостности исполняемого ПО и СЗИ | implemented | protection, configuration |
| FT071 | Целостность защищаемых данных | implemented | protection, configuration |
| FT072 | Обработка нежелательных сообщений | requires_additional_data | — |
| FT073 | Контроль неправомерной передачи данных наружу | implemented | forbidden_operation |
| FT074 | Разрешенность и корректность ввода данных | implemented | protection, configuration |
| FT075 | Ответственные и порядок работы с инцидентами | requires_evidence | — |
| FT076 | Выявление, регистрация и уведомление об инциденте | implemented | logging |
| FT077 | Причины, последствия и сохранность сведений об инциденте | requires_evidence | — |
| FT078 | Устранение последствий и предотвращение повторения | implemented | recovery |
| FT079 | Аутентификация управления виртуальной инфраструктурой | implemented | authentication |
| FT080 | Разграничение прав внутри виртуальной инфраструктуры | implemented | forbidden_operation |
| FT081 | Регистрация событий виртуализации | implemented | logging |
| FT082 | Потоки и сегментация виртуальных сред | requires_additional_data | — |
| FT083 | Доверенная загрузка виртуальной среды | implemented | configuration |
| FT084 | Управляемое перемещение виртуальных машин и данных | implemented | authorized_change |
| FT085 | Целостность конфигурации виртуальной инфраструктуры | implemented | configuration |
| FT086 | Сохранение штатного технологического режима при защите | implemented | required_operation, required_function |
| FT087 | Учет всех уровней и технологических объектов АСУ | requires_additional_data | — |
| FT088 | Периметр, эшелоны защиты и демилитаризованная зона АСУ | implemented | protection |
| FT089 | Защита ресурсов от отказа в обслуживании и вытеснения | implemented | required_function |
| FT090 | Безопасное поведение АСУ при отказе | implemented | required_function |
| FT091 | Периодическая оценка защищенности и зрелости в действующей редакции | requires_evidence | — |
| FT092 | Мониторинг безопасности и установленная отчетность | requires_evidence | — |
| FT093 | Безопасная разработка собственного программного обеспечения | requires_evidence | — |
| FT094 | Регламентированное применение искусственного интеллекта | requires_additional_data | — |
| FT095 | Подготовка персонала и отработка безопасных действий | requires_evidence | — |
| FT096 | Учет машинных носителей | requires_additional_data | — |
| FT097 | Разграничение доступа к носителю | implemented | forbidden_operation |
| FT098 | Перемещение носителя за контролируемую зону | requires_evidence | — |
| FT099 | Чтение носителя в посторонней системе | implemented | forbidden_operation |
| FT100 | Контроль интерфейсов носителей | implemented | protection |
| FT101 | Контроль операций записи и считывания с носителя | implemented | forbidden_operation |
| FT102 | Контроль подключения съемного носителя | implemented | protection |
| FT103 | Очистка носителя перед передачей, ремонтом и утилизацией | implemented | configuration |
| FT104 | Утечка по техническому каналу | requires_evidence | — |
| FT105 | Границы и состав контролируемой зоны | requires_additional_data | — |
| FT106 | Физический доступ к техническим средствам | implemented | forbidden_operation |
| FT107 | Исключение постороннего просмотра отображаемой информации | implemented | protection |
| FT108 | Защита от внешних воздействий | implemented | protection |
| FT109 | Работоспособность отказоустойчивости и резервирования | implemented | redundancy |
| FT110 | Выявление и локализация отказов технических средств | implemented | required_function |
| FT111 | Полнота и периодичность резервного копирования | implemented | recovery |
| FT112 | Доказанная возможность восстановления данных и программ | implemented | recovery |
| FT113 | Доверенная загрузка физической платформы | implemented | configuration |
| FT114 | Разделение административных и прикладных функций | implemented | forbidden_operation, incompatible_roles |
| FT115 | Неизменяемые архивы и параметры защиты | implemented | forbidden_operation, configuration |
| FT116 | Неперезаписываемый источник исполняемого ПО | implemented | configuration |
| FT117 | Изоляция процессов в памяти | implemented | protection, configuration |
| FT118 | Скрытые каналы обхода защиты | implemented | protection |
| FT119 | Подтверждение факта отправки информации | requires_additional_data | — |
| FT120 | Подтверждение факта получения информации | requires_additional_data | — |
| FT121 | Соблюдение терминального режима обработки | implemented | required_operation, configuration |
| FT122 | Документирование политик отдельных направлений защиты | requires_evidence | — |
| FT123 | Различные производители антивирусной защиты | implemented | redundancy, configuration |
| FT124 | Внутренние и внешние аудиты безопасности | requires_evidence | — |
| FT125 | Изолированное исследование подозрительного ПО | implemented | protection |
| FT126 | Сокрытие внутренних архитектурных сведений | implemented | configuration |
| FT127 | Гетерогенность и разнообразие операционных сред | implemented | redundancy, configuration |
| FT128 | Ограничение доступа к запрещенным сайтам | implemented | forbidden_operation |
| FT129 | Отсутствие неразрешенного доступа через общие ресурсы | implemented | forbidden_operation |
| FT130 | Управление жизненным циклом сетевых соединений | requires_additional_data | — |
| FT131 | Безопасность ложных компонентов | implemented | protection |
| FT132 | Обезличивание или деидентификация информации в АСУ | requires_evidence | — |
| FT133 | Маркирование аппаратных компонентов | implemented | configuration |
| FT134 | Альтернативные места хранения и обработки в нештатной ситуации | implemented | required_function, redundancy |
| FT135 | Анализ нештатных ситуаций и актуализация плана действий | requires_evidence | — |
| FT136 | Назначение ответственных и компетентность подразделения защиты | requires_evidence | — |
| FT137 | Политика, стандарты и регламенты на всем жизненном цикле | requires_evidence | — |
| FT138 | Специализированные исполнители и приемка работ защиты | requires_evidence | — |
| FT139 | Связь целей, угроз, мер и плана улучшений | requires_evidence | — |
| FT140 | Аттестация государственной информационной системы | requires_evidence | — |
| FT141 | Контроль защищенности и отчет по его результатам | requires_evidence | — |
| FT142 | Защита при работе подрядчика и изоляция его разработки | implemented | authorized_change |
| FT143 | Защита публичных сервисов ГИС от отказа в обслуживании | implemented | protection |
| FT144 | Покрытие базовыми мерами применяемых технологий ГИС | implemented | protection |
| FT145 | Соответствие мер уровню нарушителя и уровню реализации | requires_additional_data | — |
| FT149 | Сертификация, класс и сопровождение средств защиты в профиле № 117 | requires_evidence | — |
| FT150 | Доведение обязательных правил до работников и подрядчиков | requires_evidence | — |
| FT151 | Ресурсы и замкнутый цикл управления защитой | requires_evidence | — |
| FT146 | Ограниченное число контролируемых точек почтового обмена | implemented | protection |
| FT147 | Двустороннее подтверждение подлинности | implemented | authentication |
| FT148 | Анализ сетевого трафика и действий пользователей | implemented | protection |
| FT152 | Класс АСУ соответствует подтвержденным последствиям | requires_evidence | — |
| FT153 | Класс системы, инфраструктуры и сегментов в профиле № 117 | requires_evidence | — |
| NT001 | Конечные точки и направление логического канала | implemented | configuration |
| NT002 | Совместное действие маршрута и контроля доступа | implemented | forbidden_operation |
| NT003 | Разрешение имён и выбор получателя | implemented | authentication, configuration |
| NT004 | Автоматическое получение сетевой конфигурации | implemented | authentication, configuration |
| NT005 | Раздельная проверка HTTP и HTTPS | implemented | configuration, crypto |
| NT006 | Права сетевого файлового ресурса | implemented | forbidden_operation, required_operation |
| NT007 | Границы VPN и область его защиты | implemented | protection, authentication, crypto |
| NT008 | Дополнительные функции удалённого рабочего стола | implemented | forbidden_operation |
| NT009 | Возможности SSH соединения | implemented | forbidden_operation |
| NT010 | Несколько сетевых адаптеров и обход сегментации | implemented | protection, authentication |
| NT011 | Согласованность политик для разных сетевых режимов | implemented | forbidden_operation, configuration |
| NT012 | Сеанс и состояние сетевого взаимодействия | requires_additional_data | — |
| HW001 | Питание обязательных функций | implemented | required_function |
| HW002 | Охлаждение и допустимый режим оборудования | implemented | required_function, configuration |
| HW003 | Совместимость и обязательные аппаратные зависимости | implemented | required_function, configuration |
| HW004 | Изоляция оперативной памяти | implemented | forbidden_operation, protection |
| HW005 | Данные в видеопамяти и ускорителях | implemented | forbidden_operation, protection |
| HW006 | Работоспособная доверенная загрузка | implemented | configuration |
| HW007 | Изменение прошивки и её доверенных настроек | implemented | forbidden_operation, configuration, authorized_change |
| HW008 | Сохранение настроек после сброса платформы | implemented | configuration |
| HW009 | Использование TPM или альтернативной доверенной опоры | implemented | required_function, protection |
| HW010 | Физические и отладочные обходы | implemented | forbidden_operation, protection, authentication |
| PR001 | Различение функций подключённого USB устройства | implemented | forbidden_operation, configuration |
| PR002 | Подключение через концентраторы и переходники | implemented | protection |
| PR003 | Беспроводная периферия | implemented | protection, configuration, crypto |
| PR004 | Веб камера и микрофон | implemented | forbidden_operation |
| PR005 | Мониторы и интерфейсы изображения | implemented | forbidden_operation |
| PR006 | Печать и остаточные данные принтера | implemented | forbidden_operation |
| PR007 | Сканеры и импорт документов | implemented | protection, configuration |
| PR008 | Устройства ввода и сервисное управление | implemented | forbidden_operation |
| PR009 | Звуковой вывод защищаемой информации | implemented | forbidden_operation |
| PR010 | Побочные физические каналы | requires_evidence | — |
| DT001 | Распространение политики на копии данных | implemented | forbidden_operation, protection |
| DT002 | Буфер обмена временные файлы и кэш | implemented | forbidden_operation, protection |
| DT003 | Дампы памяти гибернация и диагностические файлы | implemented | forbidden_operation, protection |
| DT004 | Защита данных на выключенном накопителе и в рабочей системе | implemented | forbidden_operation, protection, crypto |
| DT005 | Наличие пригодной и достаточно свежей резервной копии | implemented | recovery, configuration |
| DT006 | Восстановимость резервной копии | implemented | recovery |
| DT007 | Время восстановления значимой функции | implemented | recovery |
| DT008 | Защита резервной копии от той же причины потери | implemented | redundancy, recovery |
| DT009 | Доступ к резервным и архивным данным | implemented | forbidden_operation |
| DT010 | Удаление данных с учётом действующих обязательств хранения | implemented | configuration |
| DT011 | Реальные потоки и наблюдение канала | implemented | quantum |
| DT012 | Пассивное получение данных и активный доступ | implemented | quantum |
| CR007 | Покрытие установленных актуальных угроз мерами защиты | implemented | protection |
| CR008 | Ответственность оператора и обработка по поручению | requires_evidence | — |
| CR009 | Оценка соответствия необходимых средств защиты | requires_evidence | — |
| CR010 | Утверждённый перечень лиц с доступом к персональным данным | requires_additional_data | — |
| CR013 | Назначение ответственного за безопасность персональных данных | requires_evidence | — |
| CR016 | Закрепление функций безопасности за подразделением | requires_evidence | — |
| CR017 | Периодический контроль выполнения требований | requires_evidence | — |
| CR011 | Защита помещений размещения ИСПДн | implemented | protection |
| CR012 | Сохранность носителей персональных данных | implemented | protection |
| CR014 | Ограничение доступа к содержанию электронного журнала | requires_additional_data | — |
| CR015 | Автоматическая регистрация изменений полномочий | implemented | logging |
| CR018 | Применимость криптографического профиля ФСБ № 378 | requires_evidence | — |
| CR019 | Соблюдение эксплуатационной документации СКЗИ | implemented | configuration |
| CR020 | Соответствие экземпляра СКЗИ и среды документированной конфигурации | implemented | configuration |
| CR021 | Утверждённые предположения о возможностях нарушителя | requires_evidence | — |
| CR022 | Совместная проверка класса СКЗИ по уровню, типу угроз и возможностям | requires_additional_data | — |
| CR023 | Отделение дополнительных сценариев от установленного порядка выбора класса | requires_additional_data | — |
| CR024 | Защита ключевой, аутентифицирующей и парольной информации СКЗИ | implemented | forbidden_operation, protection |
| CR025 | Жизненный цикл ключей по установленному регламенту | implemented | configuration |
| CR026 | Ключи в дампах памяти, журналах и резервных копиях | implemented | forbidden_operation, protection |
| CR029 | Доступность криптографической зависимости для обязательной функции | implemented | required_function, recovery |
| CR027 | Непрерывность требуемой криптографической защиты потока | implemented | crypto |
| CR028 | Разделение шифротекста и открытых представлений данных | implemented | forbidden_operation, crypto |
| CR030 | Соответствие криптографической функции требуемому свойству | implemented | configuration, crypto |
| CR031 | Двери и контроль вскрытия помещений СКЗИ | implemented | protection |
| CR032 | Правила и разрешённые лица для помещений СКЗИ | requires_additional_data | — |
| CR038 | Дополнительная защита окон и серверных помещений при УЗ 1 | implemented | protection |
| CR033 | Хранение съёмных носителей и условие исключения для шифротекста | implemented | protection, configuration |
| CR034 | Поэкземплярный учёт машинных носителей персональных данных | requires_evidence | — |
| CR035 | Регистрация запросов персональных данных и фактов их предоставления | implemented | logging |
| CR036 | Проверка работоспособности регистрации и защиты журналов | implemented | protection, logging |
| CR037 | Контроль соответствия зарегистрированных полномочий обязанностям | implemented | forbidden_operation |
| BK001 | Основание применения банковского профиля | requires_evidence | — |
| BK002 | Связь банковского актива с технологическим процессом | requires_additional_data | — |
| BK003 | Несовместимые функции банковских ролей | implemented | incompatible_roles |
| BK004 | Контроль совокупности привилегий | implemented | forbidden_operation, incompatible_roles |
| BK005 | Защита взаимодействия с внешним участником | implemented | protection, crypto |
| BK038 | Независимость и полномочия банковской службы ИБ | implemented | incompatible_roles |
| BK006 | Участие службы ИБ в жизненном цикле банковской системы | requires_evidence | — |
| BK007 | Защищаемые банковские данные в тестовой среде | implemented | forbidden_operation |
| BK008 | Возможность сопровождения поставленного компонента | requires_evidence | — |
| BK009 | Проверка защитных функций после изменения критичной АБС | requires_additional_data | — |
| BK010 | Вывод банковского компонента из эксплуатации | requires_additional_data | — |
| BK032 | Обслуживание оборудования платёжного процесса | implemented | required_function |
| BK011 | Изоляция банковских процессов разной критичности | implemented | forbidden_operation, protection |
| BK012 | Согласование изменений банковской сетевой конфигурации | implemented | authorized_change |
| BK017 | Защита банковского обмена за границей контролируемой зоны | implemented | protection, crypto |
| BK018 | Банковская архитектура антивирусной защиты | implemented | protection |
| BK019 | Целевое использование Интернета банковскими компонентами | implemented | forbidden_operation |
| BK020 | Банковский архив электронной почты | requires_additional_data | — |
| BK013 | Полнота регистрации банковских операций | implemented | logging |
| BK016 | Наблюдаемость подозрительных банковских действий | implemented | logging |
| BK037 | Прослеживаемость банковского инцидента | implemented | logging |
| BK039 | Документированная проверка и улучшение банковской защиты | requires_evidence | — |
| BK014 | Подтверждение авторства операций дистанционного обслуживания | implemented | authentication |
| BK015 | Информирование клиента об операциях от его имени | requires_additional_data | — |
| BK021 | Сохранение идентичности клиента в сеансе ДБО | implemented | authentication |
| BK031 | Защита клиента ДБО от непреднамеренной операции | requires_evidence | — |
| BK022 | Банковское основание выбора СКЗИ | requires_additional_data | — |
| BK040 | Сохранение банковского криптографического контура при изменениях | implemented | protection, configuration, crypto |
| BK023 | Описание и согласование платёжного технологического процесса | requires_additional_data | — |
| BK024 | Запрет бесконтрольного изменения платёжной информации | implemented | forbidden_operation, authorized_change |
| BK025 | Контроль результатов обработки платёжной информации | implemented | configuration |
| BK026 | Подлинность и неизменность платёжного сообщения | implemented | configuration, crypto |
| BK027 | Контроль ввода и параметров платёжной операции | implemented | configuration |
| BK028 | Сверка межбанковского сообщения с обработанным основанием | implemented | configuration |
| BK029 | Возможность блокировать приём распоряжения клиента | implemented | required_operation |
| BK030 | Доставка и восстановление платёжной информации | implemented | required_operation, recovery |
| BK033 | Контроль устройств в общедоступной зоне | implemented | protection |
| BK034 | Защита неплатёжного банковского процесса | implemented | forbidden_operation, protection |
| BK035 | Обоснование риска и способа его обработки | requires_evidence | — |
| BK036 | Непрерывность критичного банковского процесса | implemented | required_operation, required_function, redundancy, recovery |
| CR039 | Явные возможности и горизонт квантового сценария | unsupported | — |
| CR040 | Раскрытие наблюдаемого трафика в квантовом сценарии | implemented | quantum |
| CR041 | Долговременная конфиденциальность и отложенное раскрытие | implemented | quantum |
| CR042 | Подмена подписи и аутентификации как отдельный сценарий | unsupported | — |
| CR043 | Зависимость защиты хранимых данных от защиты ключа | unsupported | — |
| CR044 | Отдельная оценка симметрических алгоритмов и хеширования | implemented | quantum |
| CR045 | Совместимость сторон и обход через резервный криптографический режим | implemented | crypto |
| CR046 | Проверка состава гибридного механизма | unsupported | — |
| CR047 | Разделение сценарной стойкости и нормативной допустимости средства | unsupported | — |
| RP001 | Различение причины нарушения и затронутого ресурса | unsupported | — |
| RP002 | Допустимость предлагаемого действия | unsupported | — |
| RP003 | Подтверждённое устранение конкретного нарушения | unsupported | — |
| RP004 | Сохранение обязательных функций после исправления | unsupported | — |
| RP005 | Отсутствие новых нарушений | unsupported | — |
| RP006 | Неизменность требований во время подбора исправления | unsupported | — |
| RP007 | Совместное действие нескольких исправлений | unsupported | — |
| RP008 | Безопасность промежуточных состояний | unsupported | — |
| RP009 | Сохранение возможности отката и восстановления | unsupported | — |
| RP010 | Обоснование стоимости и минимальности | unsupported | — |
| RS001 | Разделение типов результата | unsupported | — |
| RS002 | Проверяемое объяснение нарушения | unsupported | — |
| RS003 | Проверка подграфа с учётом его границы | unsupported | — |
| RS004 | Неполная проверка при ограниченном бюджете | unsupported | — |
| RS005 | Сравнение конфигураций и устойчивость объяснения | unsupported | — |
| RS006 | Общий результат без потери частных ограничений | unsupported | — |


## Проверка и воспроизведение

```bash
.venv-analyzer/bin/python -m pytest -q tests/test_catalog.py
.venv-analyzer/bin/python - <<'PY'
from analyzer.catalog import write_registry, coverage
catalog = write_registry(
    'data/sources/katalog_pravil_logicheskogo_analizatora.docx',
    'data/rule_registry.json',
)
print(catalog['rule_count'], catalog['section_count'], catalog['date'])
print(coverage(catalog)['summary'])
PY
```

Проверяются фактический состав, сохранность исходных полей, происхождение, отсутствие переноса приложений в последнюю запись, дублирующиеся ID, TXT/DOCX roundtrip, неизвестная применимость, частичный PASS, достаточный FAIL и различие UNKNOWN, REQUIRES_EVIDENCE и NOT_CHECKED. Поведение самих проверяющих модулей проверяется в `tests/test_engine.py`, поиск исправлений — в `tests/test_repairs.py`.
