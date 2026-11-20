/* Complete graph rendering. Security decisions come from the analyzer payload. */
(() => {
    'use strict';
    const SVG = 'http://www.w3.org/2000/svg';
    let instance = 0;
    const text = (tag, value, cls) => { const e = document.createElement(tag); if (value != null) e.textContent = value; if (cls) e.className = cls; return e; };
    const svg = (tag, attrs = {}) => { const e = document.createElementNS(SVG, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v)); return e; };
    const compare = (a, b) => String(a).localeCompare(String(b), 'ru', {numeric: true});
    const LAYERS = {physical: {name: 'Физический', code: 'F', color: '#2563eb'}, syntactic: {name: 'Синтаксический', code: 'L', color: '#7c3aed'}, semantic: {name: 'Семантический', code: 'S', color: '#078574'}};
    const clusterOf = node => String(node.cluster || node.pc || node.group || 'shared');
    const combinedValue = edges => edges.some(edge => edge.value === 'TRUE') ? 'TRUE' : edges.some(edge => edge.value !== 'FALSE') ? 'UNKNOWN' : 'FALSE';
    const actor = n => (n.types || []).includes('subject') || /^(Пользователь|Администратор)(?:\s|$)/i.test(n.name || ''); // icon only, never a security classification
    const uncertain = n => n.present === 'UNKNOWN' || (n.unknowns || []).length > 0;
    const trouble = n => (n.causes || []).length > 0 || (n.affected || []).length > 0;
    const yesno = v => ({TRUE: 'да', FALSE: 'нет', UNKNOWN: 'неизвестно'}[v] || String(v));
    const actionNames = {restore_filter: 'Восстановлен межсетевой экран', enable_logger: 'Включена регистрация событий', close_application_acl: 'Закрыт доступ через приложение', close_vpn_acl: 'Закрыт доступ через VPN', disable_nas: 'Отключён NAS'};
    const fieldNames = {present: 'Присутствие', enabled: 'Включён', healthy: 'Исправен', acl: 'Разрешение доступа', available: 'Работоспособность', parameter: 'Параметр', cover: 'Защита', logger: 'Регистрация'};
    function button(label, callback, cls = '') { const b = text('button', label, `sg-button ${cls}`); b.type = 'button'; b.addEventListener('click', callback); return b; }
    function fallback(state) {
        const m = state?.model || {};
        return {nodes: Object.entries(m.nodes || {}).map(([key, n]) => ({...n, key, present: 'UNKNOWN'})), edges: [], findings: [], summary: {}, diagnostics: [{message: 'В этом отчёте нет данных связей. Загрузите исходную модель или запустите сценарий заново.'}]};
    }
    function arrange(graphs, compact = false, clusterName = key => key === 'shared' ? 'Общие ресурсы' : key) {
        const all = new Map();
        for (const g of graphs) for (const n of g.nodes || []) if (!all.has(n.key)) all.set(n.key, n);
        const groups = new Map();
        for (const n of all.values()) { const key = clusterOf(n); if (!groups.has(key)) groups.set(key, []); groups.get(key).push(n); }
        const positions = new Map(), boxes = [];
        const locals = [...groups.keys()].filter(k => k !== 'shared').sort(compare);
        const order = [...locals, ...(groups.has('shared') ? ['shared'] : [])];
        const large = all.size > 40, width = compact && large ? 2720 : large ? 1900 : 1000;
        let y = 40;
        let rowBottom = y;
        for (let i = 0; i < order.length; i++) {
            const name = order[i], ns = groups.get(name).sort((a, b) => Number(actor(b)) - Number(actor(a)) || compare(a.key, b.key));
            const shared = name === 'shared';
            const columns = large ? (shared ? Math.min(compact ? 16 : 10, Math.max(1, ns.length)) : compact ? 10 : 7) : Math.min(5, Math.max(1, ns.length));
            const rows = Math.ceil(ns.length / columns);
            const rowHeight = large ? compact ? 82 : 92 : 130;
            const blockW = large && !shared ? (width - 120) / 2 : width - 80;
            const blockH = (compact ? 65 : 95) + rows * rowHeight;
            let x = 40;
            if (large && !shared) {
                x = 40 + (i % 2) * (blockW + 40);
                if (compact) {
                    if (i > 0 && i % 2 === 0) y = rowBottom + 32;
                    rowBottom = Math.max(rowBottom, y + blockH);
                } else y = 40 + Math.floor(i / 2) * 970;
            } else if (shared && large) y = compact ? rowBottom + 32 : 40 + Math.ceil(locals.length / 2) * 970;
            boxes.push({x, y, width: blockW, height: blockH, name: clusterName(name), count: ns.length});
            ns.forEach((n, j) => positions.set(n.key, {x: x + (j % columns + .5) * blockW / columns, y: y + (compact ? 67 : 80) + Math.floor(j / columns) * rowHeight}));
            if (!large) y += blockH + 30;
        }
        return {positions, boxes, width, height: Math.max(430, ...boxes.map(b => b.y + b.height + 40)), nodes: all};
    }
    function mount(container, report, options = {}) {
        container.replaceChildren();
        const id = ++instance, cleanups = [], panes = [], compact = Boolean(options.compact);
        const states = report.states || {};
        const beforeName = states[options.beforeState] && options.beforeState !== 'repaired' ? options.beforeState : ['experiment', 'changed', 'before', 'uploaded', 'imported', 'baseline'].find(k => states[k]) || Object.keys(states).find(k => k !== 'repaired');
        const beforeState = states[beforeName];
        if (!beforeState) { container.append(text('p', 'Нет состояния для построения графа.', 'sg-note')); return {setPhase() { return 'before'; }, focusNodes() {}, focusProblem() {}, getView() { return 'all'; }, setView() { return 'all'; }, getViewState() { return {view: 'all'}; }, destroy() { container.replaceChildren(); }}; }
        const before = beforeState.graph || fallback(beforeState), afterState = states.repaired, after = afterState?.graph || (afterState ? fallback(afterState) : null);
        const allNodes = new Map();
        for (const graph of [before, ...(after ? [after] : [])]) for (const node of graph.nodes || []) allNodes.set(node.key, node);
        const clusterNames = new Map();
        for (const graph of [before, ...(after ? [after] : [])]) for (const cluster of graph.clusters || []) clusterNames.set(String(cluster.id), cluster.name || cluster.id);
        const clusters = [...new Set([...allNodes.values()].map(clusterOf))].sort(compare);
        const clusterName = key => clusterNames.get(key) || (key === 'shared' ? 'Общие ресурсы' : key);
        const hasLayers = [before, after].some(graph => graph?.layer_edges?.length);
        const savedView = options.viewState || {};
        let selectedView = savedView.view || 'all';
        let matrixLayer = LAYERS[savedView.matrixLayer] ? savedView.matrixLayer : 'physical';
        let matrixQuery = String(savedView.matrixQuery || ''), rowPage = Number(savedView.rowPage) || 0, columnPage = Number(savedView.columnPage) || 0;
        let showLegacy = !hasLayers || savedView.showLegacy === true;
        let layout = arrange([before, ...(after ? [after] : [])], compact, clusterName);
        const beforeEdges = new Map((before.edges || []).map(e => [e.id, e]));
        const failures = (before.findings || []).filter(f => f.status === 'FAIL');
        const afterById = new Map((after?.findings || []).map(f => [f.id, f]));
        const cleared = new Set((before.nodes || []).filter(n => n.is_violator && (n.violations || []).length && n.violations.every(k => afterById.get(k)?.status === 'PASS')).map(n => n.key));
        const root = text('section', null, `sg-comparison${compact ? ' sg-compact' : ''}`); root.dataset.graphComparison = String(id); container.append(root);
        let activePhase = options.phase === 'after' && after ? 'after' : 'before';
        root.dataset.graphPhase = activePhase;
        const intro = text('div', null, `sg-story ${failures.length ? '' : 'sg-story-neutral'}`);
        if (failures.length) {
            intro.append(text('h3', 'Где нарушена безопасность'));
            const list = text('ul');
            for (const f of [...failures].sort((a, b) => Number(Boolean(b.offender)) - Number(Boolean(a.offender)))) {
                const li = text('li', f.message || f.name); li.className = f.offender ? 'sg-offender-story' : '';
                list.append(li);
            }
            intro.append(list);
        } else {
            intro.append(text('h3', 'Компоненты и связи системы'));
            intro.append(text('p', (before.findings || []).length ? 'Подтверждённых нарушений в выбранном состоянии нет. Неизвестные условия отмечены отдельно.' : 'Граф показывает исходные связи. Без заданных прав и требований нельзя определить нарушителя.'));
        }
        if (!compact) root.append(intro);
        const toolbar = text('div', null, 'sg-global-controls');
        const search = text('input'); search.type = 'search'; search.placeholder = 'Найти пользователя или компонент'; search.setAttribute('aria-label', 'Найти узел графа');
        const found = text('div', null, 'sg-search-results'); found.hidden = true;
        toolbar.append(search, button('Найти', searchNodes));
        if (!compact) toolbar.append(button('Весь граф', () => changeView(fullView())), button('К нарушению', focusProblem));
        else {
            const plus = button('+', () => zoom(.75)); plus.setAttribute('aria-label', 'Увеличить граф');
            const minus = button('−', () => zoom(1.33)); minus.setAttribute('aria-label', 'Уменьшить граф');
            toolbar.append(plus, minus, button('Вписать', () => changeView(fullView())));
        }
        root.append(toolbar, found);
        for (const control of toolbar.querySelectorAll('button')) if (control.textContent !== 'Найти') control.dataset.graphOnly = 'true';
        const legend = text('div', null, 'sg-legend');
        for (const [cls, label] of [['violator', 'Пользователь с запрещённым доступом'], ['normal', 'Компонент'], ['warning', 'Проблема или неизвестность'], ['fixed', 'Исправлено'], ['blocked', 'Доступ перекрыт']]) {
            const item = text('span'); item.append(text('i', null, `sg-key sg-key-${cls}`), text('span', label)); legend.append(item);
        }
        if (!compact) {
            root.append(legend);
            root.append(text('p', 'Серые линии — исходные связи, красный путь — доказанный запрещённый доступ. Масштаб: колесо или кнопки. Перемещение: перетаскивание. Нажмите узел для объяснения.', 'sg-hint'));
        }
        const viewTabs = text('div', null, 'sg-view-tabs'); viewTabs.setAttribute('role', 'tablist'); viewTabs.setAttribute('aria-label', 'Представление системы');
        const views = [{id: 'all', name: 'Вся система'}, ...clusters.map(key => ({id: 'cluster:' + key, name: clusterName(key)})), {id: 'clusters', name: clusters.every(key => /^ПК\s*\d/i.test(clusterName(key)) || key === 'shared') ? 'Между ПК' : 'Кластеры'}, {id: 'matrices', name: 'Матрицы'}];
        if (!views.some(item => item.id === selectedView)) selectedView = 'all';
        const viewButtons = new Map();
        for (const item of views) {
            const tab = button(item.name, () => setView(item.id)); tab.setAttribute('role', 'tab'); tab.id = `sg-${id}-view-${viewButtons.size}`;
            tab.dataset.view = item.id; tab.setAttribute('aria-controls', `sg-${id}-view-panel`); viewButtons.set(item.id, tab); viewTabs.append(tab);
        }
        keyboardTabs(viewTabs);
        root.insertBefore(viewTabs, toolbar);
        const layerLegend = text('div', null, 'sg-layer-legend'); layerLegend.setAttribute('aria-label', 'Уровни и типы связей');
        for (const [key, info] of Object.entries(LAYERS)) { const item = text('span'); const line = text('i', null, 'sg-layer-key'); line.style.setProperty('--layer-color', info.color); item.append(line, text('span', `${info.code} · ${info.name}`)); item.dataset.layer = key; layerLegend.append(item); }
        const protectedLegend = text('span'); protectedLegend.append(text('i', null, 'sg-layer-key sg-layer-key-protected'), text('span', 'Через защитный компонент')); layerLegend.append(protectedLegend);
        layerLegend.append(text('span', '? — неизвестно; 0 — не действует', 'sg-layer-state-key'));
        layerLegend.hidden = !hasLayers; root.append(layerLegend);
        const rawDetails = text('details', null, 'sg-source-options'); rawDetails.hidden = !hasLayers;
        rawDetails.append(text('summary', 'Исходные связи'));
        const rawLabel = text('label'), rawCheckbox = text('input'); rawCheckbox.type = 'checkbox'; rawCheckbox.checked = showLegacy;
        rawCheckbox.addEventListener('change', () => { showLegacy = rawCheckbox.checked; renderGraphs(); });
        rawLabel.append(rawCheckbox, document.createTextNode('Показать исходные и семантические связи серым')); rawDetails.append(rawLabel); root.append(rawDetails);
        const viewPanel = text('div', null, 'sg-view-panel'); viewPanel.id = `sg-${id}-view-panel`; viewPanel.setAttribute('role', 'tabpanel'); root.append(viewPanel);
        const grid = text('div', null, `sg-grid ${compact || !failures.length && !after && !report.repair ? 'sg-single' : ''}`); viewPanel.append(grid);
        const inspector = text('aside', null, 'sg-inspector'); inspector.setAttribute('aria-live', 'polite');
        inspector.hidden = compact;
        if (!compact) inspector.append(text('strong', 'Выберите узел на графе'), text('p', 'Здесь появятся его название, состояние, связанные нарушения и изменения.'));
        root.append(inspector);
        const matrixPanel = text('section', null, 'sg-matrices'); matrixPanel.hidden = true; viewPanel.append(matrixPanel);
        const matrixPhase = text('p', null, 'sg-matrix-phase'); matrixPanel.append(matrixPhase);
        const matrixTabs = text('div', null, 'sg-matrix-tabs'); matrixTabs.setAttribute('role', 'tablist'); matrixTabs.setAttribute('aria-label', 'Уровень матрицы');
        const matrixButtons = new Map();
        for (const [key, info] of Object.entries(LAYERS)) { const tab = button(`${info.code} · ${info.name}`, () => { matrixLayer = key; renderMatrix(); }); tab.dataset.layer = key; tab.id = `sg-${id}-matrix-${key}`; tab.setAttribute('role', 'tab'); tab.setAttribute('aria-controls', `sg-${id}-matrix-body`); matrixButtons.set(key, tab); matrixTabs.append(tab); }
        keyboardTabs(matrixTabs); matrixPanel.append(matrixTabs);
        const matrixTools = text('div', null, 'sg-matrix-tools'), matrixSearch = text('input'); matrixSearch.type = 'search'; matrixSearch.placeholder = 'Узлы строк и столбцов'; matrixSearch.value = matrixQuery; matrixSearch.setAttribute('aria-label', 'Фильтр матрицы');
        matrixSearch.addEventListener('input', () => { matrixQuery = matrixSearch.value; rowPage = 0; columnPage = 0; renderMatrix(); });
        matrixTools.append(matrixSearch, button('CSV всех каналов', exportMatrices)); matrixPanel.append(matrixTools);
        matrixPanel.append(text('p', 'Строка — источник, столбец — получатель. 1: уровень действует хотя бы у одного объявленного канала; 0: уровень не действует ни у одного из объявленных каналов; ?: действие уровня неизвестно; —: канал не объявлен. ↝: явно указан защитный маршрут. Разные каналы не объединяются в один FLS-канал; состав — в подсказке ячейки. Значения относятся к выбранному состоянию.', 'sg-matrix-note'));
        const matrixBody = text('div'); matrixBody.id = `sg-${id}-matrix-body`; matrixBody.setAttribute('role', 'tabpanel'); matrixPanel.append(matrixBody);
        let view = fullView(), selectedKey = allNodes.has(savedView.selectedKey) ? savedView.selectedKey : null;
        function keyboardTabs(tabs) {
            tabs.addEventListener('keydown', event => { if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return; const buttons = [...tabs.querySelectorAll('[role="tab"]')]; const index = buttons.indexOf(document.activeElement); if (index < 0) return; event.preventDefault(); const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + buttons.length) % buttons.length; buttons[next].click(); buttons[next].focus(); });
        }
        function currentGraph() { return activePhase === 'after' && after ? after : before; }
        function revealTab(tabs, tab) {
            const bar = tabs.getBoundingClientRect(), item = tab.getBoundingClientRect();
            if (item.left < bar.left) tabs.scrollLeft -= bar.left - item.left;
            else if (item.right > bar.right) tabs.scrollLeft += item.right - bar.right;
        }
        function getViewState() { return {view: selectedView, matrixLayer, matrixQuery, rowPage, columnPage, showLegacy, selectedKey}; }
        function setView(next) {
            selectedView = views.some(item => item.id === next) ? next : 'all'; root.dataset.graphView = selectedView;
            for (const [key, tab] of viewButtons) { const selected = key === selectedView; tab.setAttribute('aria-selected', String(selected)); tab.tabIndex = selected ? 0 : -1; }
            revealTab(viewTabs, viewButtons.get(selectedView));
            for (const control of toolbar.querySelectorAll('[data-graph-only]')) control.hidden = selectedView === 'matrices';
            viewPanel.setAttribute('aria-labelledby', viewButtons.get(selectedView).id);
            grid.hidden = selectedView === 'matrices'; matrixPanel.hidden = selectedView !== 'matrices'; inspector.hidden = true;
            rawDetails.hidden = !hasLayers || selectedView === 'matrices';
            if (selectedView === 'matrices') renderMatrix(); else renderGraphs();
            if (typeof options.onViewChange === 'function') options.onViewChange(getViewState());
            return selectedView;
        }
        function filteredGraph(graph) {
            if (selectedView === 'all') return graph;
            if (selectedView === 'clusters') return aggregateGraph(graph);
            const key = selectedView.slice(8), nodes = (graph.nodes || []).filter(node => clusterOf(node) === key), keys = new Set(nodes.map(node => node.key));
            const inside = edge => keys.has(edge.source) && keys.has(edge.target);
            const crossing = edge => keys.has(edge.source) !== keys.has(edge.target);
            const channels = new Set((graph.layer_edges || []).filter(crossing).map(edge => edge.channel_id || edge.id));
            const rawCount = (graph.edges || []).filter(edge => edge.kind === 'structural' && crossing(edge)).length;
            return {...graph, nodes, edges: (graph.edges || []).filter(inside), layer_edges: (graph.layer_edges || []).filter(inside), boundary: {channels: channels.size, edges: rawCount}};
        }
        function aggregateGraph(graph) {
            const members = new Map(); for (const node of graph.nodes || []) { const key = clusterOf(node); if (!members.has(key)) members.set(key, []); members.get(key).push(node); }
            const keys = new Map((graph.nodes || []).map(node => [node.key, clusterOf(node)]));
            const groups = new Map();
            for (const edge of graph.layer_edges || []) { const source = keys.get(edge.source), target = keys.get(edge.target); if (!source || !target || source === target) continue; const key = JSON.stringify([source, target, edge.layer, edge.via_protection === true]); if (!groups.has(key)) groups.set(key, []); groups.get(key).push(edge); }
            const layer_edges = [...groups].map(([key, edges]) => { const [source, target, layer] = JSON.parse(key); return {id: 'cluster:' + key, channel_id: 'cluster:' + key, source: '@cluster:' + source, target: '@cluster:' + target, layer, value: combinedValue(edges), via_protection: edges.every(edge => edge.via_protection), protection_via: [...new Set(edges.flatMap(edge => edge.protection_via || []))], aggregate: true, channel_count: edges.length, protected_count: edges.filter(edge => edge.via_protection).length, values: {TRUE: edges.filter(edge => edge.value === 'TRUE').length, FALSE: edges.filter(edge => edge.value === 'FALSE').length, UNKNOWN: edges.filter(edge => !['TRUE', 'FALSE'].includes(edge.value)).length}}; });
            const raw = new Map(); for (const edge of graph.edges || []) { const source = keys.get(edge.source), target = keys.get(edge.target); if (!source || !target || source === target) continue; const key = JSON.stringify([source, target]); if (!raw.has(key)) raw.set(key, {id: 'cluster-raw:' + key, source: '@cluster:' + source, target: '@cluster:' + target, kind: 'structural', value: 'UNKNOWN', label: 'Исходные связи между кластерами', count: 0}); raw.get(key).count++; }
            const nodes = [...members].map(([key, ns]) => ({key: '@cluster:' + key, name: clusterName(key), cluster: 'shared', aggregateCluster: key, memberCount: ns.length, present: 'TRUE', is_violator: false, affected: ns.some(node => node.is_violator || trouble(node)) ? ['cluster-findings'] : [], unknowns: ns.some(uncertain) ? ['cluster-unknowns'] : [], types: []}));
            return {...graph, nodes, edges: [...raw.values()], layer_edges, diagnostics: []};
        }
        function renderGraphs() {
            panes.length = 0; grid.replaceChildren();
            const first = filteredGraph(before), second = after ? filteredGraph(after) : null;
            layout = arrange([first, ...(second ? [second] : [])], compact, clusterName);
            if (selectedView === 'clusters') {
                const count = layout.nodes.size, radius = Math.max(180, count * 36); layout.width = radius * 2 + 360; layout.height = radius * 2 + 260; layout.boxes = [];
                [...layout.nodes.keys()].sort(compare).forEach((key, index) => { const angle = count === 1 ? 0 : 2 * Math.PI * index / count - Math.PI / 2; layout.positions.set(key, {x: layout.width / 2 + (count === 1 ? 0 : Math.cos(angle) * radius), y: layout.height / 2 + (count === 1 ? 0 : Math.sin(angle) * radius)}); });
            }
            pane(first, 'before'); if (second) pane(second, 'after');
            else if (!compact && (failures.length || report.repair)) {
                const placeholder = text('section', null, 'sg-pane sg-placeholder'); placeholder.dataset.graphPhase = 'after';
                placeholder.append(text('h4', 'После исправления'), text('p', report.repair ? 'Поиск не дал подтверждённого исправления. Исходное состояние сохранено.' : 'Проверенный граф появится после применения и повторной проверки исправления.'));
                if (options.onRepair) {
                    const repairButton = button('Устранить уязвимость', async () => { repairButton.disabled = true; try { await options.onRepair(); } catch (error) { placeholder.append(text('p', error.message || 'Не удалось выполнить исправление.', 'sg-diagnostic')); repairButton.disabled = false; } }, 'sg-primary');
                    repairButton.dataset.repairGraph = 'true'; repairButton.disabled = Boolean(options.busy); placeholder.append(repairButton);
                }
                grid.append(placeholder);
            }
            changeView(fullView()); setPhase(activePhase);
        }
        function matrixIndex(graph, layer) {
            const index = new Map(); for (const edge of graph.layer_edges || []) { if (edge.layer !== layer) continue; const key = JSON.stringify([edge.source, edge.target]); if (!index.has(key)) index.set(key, []); index.get(key).push(edge); } return index;
        }
        function renderMatrix() {
            const graph = currentGraph(), pageSize = 30, query = matrixQuery.trim().toLocaleLowerCase('ru');
            const nodes = (graph.nodes || []).filter(node => `${node.key} ${node.name || ''} ${clusterName(clusterOf(node))}`.toLocaleLowerCase('ru').includes(query)).sort((a, b) => compare(a.key, b.key));
            const pages = Math.max(1, Math.ceil(nodes.length / pageSize)); rowPage = Math.max(0, Math.min(pages - 1, rowPage)); columnPage = Math.max(0, Math.min(pages - 1, columnPage));
            matrixPhase.textContent = `${activePhase === 'after' ? 'После исправления' : 'До исправления'} · ${nodes.length} узлов · ${LAYERS[matrixLayer].name.toLocaleLowerCase('ru')} уровень`;
            for (const [key, tab] of matrixButtons) { tab.setAttribute('aria-selected', String(key === matrixLayer)); tab.tabIndex = key === matrixLayer ? 0 : -1; }
            revealTab(matrixTabs, matrixButtons.get(matrixLayer));
            matrixBody.setAttribute('aria-labelledby', matrixButtons.get(matrixLayer).id); matrixBody.replaceChildren();
            if (!(graph.layer_edges || []).length) matrixBody.append(text('p', 'Уровни связей не заданы. Исходные линии графа не распределяются по F/L/S автоматически.', 'sg-matrix-note'));
            const navigation = text('div', null, 'sg-matrix-pagination');
            for (const [axis, page] of [['row', rowPage], ['column', columnPage]]) { const group = text('div'); const name = axis === 'row' ? 'Строки' : 'Столбцы'; const previous = button('←', () => { if (axis === 'row') rowPage--; else columnPage--; renderMatrix(); }); previous.setAttribute('aria-label', `${name}: предыдущая страница`); previous.disabled = page === 0; const next = button('→', () => { if (axis === 'row') rowPage++; else columnPage++; renderMatrix(); }); next.setAttribute('aria-label', `${name}: следующая страница`); next.disabled = page + 1 >= pages; group.append(previous, text('span', `${name}: ${nodes.length ? page * pageSize + 1 : 0}–${Math.min((page + 1) * pageSize, nodes.length)} из ${nodes.length}`), next); navigation.append(group); }
            matrixBody.append(navigation);
            const scroll = text('div', null, 'sg-matrix-scroll'); scroll.tabIndex = 0; scroll.setAttribute('role', 'region'); scroll.setAttribute('aria-label', 'Матрица, прокрутка по горизонтали');
            const table = text('table', null, 'sg-matrix'); table.dataset.matrixLayer = matrixLayer; const caption = text('caption', `${LAYERS[matrixLayer].code}: источник по строке → получатель по столбцу`); table.append(caption);
            const columns = nodes.slice(columnPage * pageSize, (columnPage + 1) * pageSize), rows = nodes.slice(rowPage * pageSize, (rowPage + 1) * pageSize), index = matrixIndex(graph, matrixLayer);
            const thead = text('thead'), headings = text('tr'); headings.append(text('th', 'Источник ↓ / Получатель →'));
            for (const node of columns) { const cell = text('th', (node.name || node.key).slice(0, 18)); cell.scope = 'col'; cell.title = `${node.name || node.key} · ${node.key}`; cell.setAttribute('aria-label', cell.title); headings.append(cell); } thead.append(headings); table.append(thead);
            const tbody = text('tbody'); for (const source of rows) { const row = text('tr'), label = text('th', source.name || source.key); label.scope = 'row'; label.title = source.key; row.append(label);
                for (const target of columns) { const edges = index.get(JSON.stringify([source.key, target.key])) || [], value = edges.length ? combinedValue(edges) : 'UNDECLARED'; const symbol = {TRUE: '1', FALSE: '0', UNKNOWN: '?', UNDECLARED: '—'}[value]; const protectedRoute = edges.some(edge => edge.via_protection); const cell = text('td', symbol + (protectedRoute ? ' ↝' : ''), `sg-matrix-value sg-matrix-${value.toLowerCase()}`); cell.dataset.source = source.key; cell.dataset.target = target.key; cell.dataset.value = value; cell.dataset.viaProtection = String(protectedRoute);
                    cell.title = `${source.name || source.key} → ${target.name || target.key}\n${edges.length ? edges.map(edge => `${edge.channel_id || edge.id}: ${edge.value}; исходное: ${edge.declared_value || edge.value}${edge.via_protection ? '; защита: ' + (edge.protection_via || []).join(', ') : ''}`).join('\n') : 'Канал не объявлен. Это не доказанное отсутствие связи.'}`; cell.setAttribute('aria-label', cell.title); row.append(cell); } tbody.append(row); }
            table.append(tbody); scroll.append(table); matrixBody.append(scroll);
        }
        function exportMatrices() {
            const graph = currentGraph(), names = new Map((graph.nodes || []).map(node => [node.key, node.name || node.key]));
            const quote = value => { let string = String(value ?? ''); if (/^\s*[=+@-]/.test(string) || /^[\t\r\n]/.test(string)) string = "'" + string; return '"' + string.replaceAll('"', '""') + '"'; };
            const rows = [['state', 'layer', 'source', 'source_name', 'target', 'target_name', 'value', 'declared_value', 'via_protection', 'protection_via', 'channel_id']];
            for (const edge of graph.layer_edges || []) rows.push([activePhase, edge.layer, edge.source, names.get(edge.source), edge.target, names.get(edge.target), edge.value, edge.declared_value || edge.value, Boolean(edge.via_protection), (edge.protection_via || []).join(' | '), edge.channel_id || edge.id]);
            const url = URL.createObjectURL(new Blob(['\ufeff' + rows.map(row => row.map(quote).join(',')).join('\r\n')], {type: 'text/csv;charset=utf-8'})); const link = text('a'); link.href = url; link.download = `graph-matrices-${activePhase}.csv`; root.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
        }
        function fullView() { return {x: 0, y: 0, width: layout.width, height: layout.height}; }
        function changeView(next) { view = next; for (const p of panes) p.svg.setAttribute('viewBox', `${view.x} ${view.y} ${view.width} ${view.height}`); }
        function zoom(factor) { const w = view.width * factor, h = view.height * factor; if (w < layout.width / 14 || w > layout.width * 2) return; changeView({x: view.x + (view.width - w) / 2, y: view.y + (view.height - h) / 2, width: w, height: h}); }
        function setPhase(phase) {
            activePhase = phase === 'after' && after ? 'after' : 'before';
            root.dataset.graphPhase = activePhase;
            for (const p of panes) {
                p.box.hidden = compact && p.phase !== activePhase;
                if (p.box.hidden) p.box.classList.remove('sg-expanded');
                p.box.setAttribute('aria-hidden', String(p.box.hidden));
            }
            if (selectedView === 'matrices') renderMatrix();
            else if (selectedKey && layout.nodes.has(selectedKey)) inspect(selectedKey, false);
            return activePhase;
        }
        function focusKeys(keys) {
            const valid = keys.filter(key => allNodes.has(key));
            if (valid.length && (selectedView === 'matrices' || selectedView === 'clusters' || valid.some(key => !layout.nodes.has(key)))) { const groups = new Set(valid.map(key => clusterOf(allNodes.get(key)))); setView(groups.size === 1 ? 'cluster:' + [...groups][0] : 'all'); }
            const points = [...new Set(keys)].map(k => layout.positions.get(k)).filter(Boolean); if (!points.length) return;
            const xs = points.map(p => p.x), ys = points.map(p => p.y);
            let w = Math.max(350, Math.max(...xs) - Math.min(...xs) + 250), h = Math.max(350, Math.max(...ys) - Math.min(...ys) + 250);
            const ratio = layout.width / layout.height; if (w / h < ratio) w = h * ratio; else h = w / ratio;
            changeView({x: (Math.max(...xs) + Math.min(...xs) - w) / 2, y: (Math.max(...ys) + Math.min(...ys) - h) / 2, width: w, height: h});
        }
        function focusProblem() {
            const currentFailures = compact && activePhase === 'after' ? (after.findings || []).filter(f => f.status === 'FAIL') : failures;
            focusKeys(currentFailures.flatMap(f => [f.offender, f.object, ...(f.path || []), ...(f.causes || [])]).filter(Boolean));
        }
        function searchNodes() {
            const query = search.value.trim().toLocaleLowerCase('ru'); found.replaceChildren(); found.hidden = !query;
            if (!query) return;
            const matches = [...allNodes.values()].filter(n => `${n.key} ${n.name} ${clusterName(clusterOf(n))}`.toLocaleLowerCase('ru').includes(query));
            if (!matches.length) { found.append(text('p', 'Компонент не найден.')); return; }
            for (const n of matches.slice(0, 12)) found.append(button(`${n.name} · ${n.pc || 'Общий'} · ${n.key}`, () => { focusKeys([n.key]); inspect(n.key); found.hidden = true; }));
            if (matches.length > 12) found.append(text('p', `Найдено ${matches.length}. Уточните название.`));
            if (matches.length === 1) { focusKeys([matches[0].key]); inspect(matches[0].key); }
        }
        search.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); searchNodes(); } });
        function inspect(key, notify = true) {
            const n = layout.nodes.get(key); if (!n) return;
            if (n.aggregateCluster != null) { setView('cluster:' + n.aggregateCluster); return; }
            selectedKey = key; inspector.replaceChildren();
            inspector.hidden = false;
            inspector.append(text('h4', `${n.name} · ${clusterName(clusterOf(n))}`));
            if (!compact) inspector.append(text('span', key, 'sg-node-id'));
            const columns = text('div', null, 'sg-inspector-columns');
            const snapshots = compact ? [[activePhase === 'after' ? after : before, '']] : [[before, after ? 'До исправления' : 'Текущее состояние'], ...(after ? [[after, 'После исправления']] : [])];
            for (const [g, title] of snapshots) {
                const current = g.nodes.find(item => item.key === key); if (!current) continue;
                const cell = text('div'); if (title) cell.append(text('strong', title));
                const status = current.is_violator ? 'Доказан запрещённый доступ' : g === after && cleared.has(key) ? 'Запрещённый доступ устранён' : trouble(current) ? 'Связан с нарушением требования' : uncertain(current) ? 'Есть неизвестные условия' : 'Доказанный запрещённый доступ не найден';
                cell.append(text('p', status));
                for (const [field, caption] of [['security_label', 'Метка конфиденциальности'], ['clearance', 'Допуск'], ['integrity_label', 'Метка целостности']]) {
                    const label = current[field];
                    if (label && typeof label === 'object') cell.append(text('p', `${caption}: ${label.level || 'уровень неизвестен'} · категории: ${Array.isArray(label.categories) ? (label.categories.join(', ') || 'нет') : 'неизвестны'}.`, 'sg-security-label'));
                }
                if (!compact || current.present !== 'TRUE' || current.available !== 'TRUE') cell.append(text('p', `Присутствует: ${yesno(current.present)}. Работоспособность: ${yesno(current.available)}.`));
                for (const f of g.findings || []) if ([f.object, f.subject, f.offender, ...(f.causes || [])].includes(key) && f.status !== 'PASS') cell.append(text('p', f.message || f.name));
                for (const c of current.changes || []) cell.append(text('p', `${fieldNames[c.predicate] || c.predicate}: ${yesno(c.before)} → ${yesno(c.after)}.`));
                columns.append(cell);
            }
            inspector.append(columns);
            for (const pane of panes) for (const [nodeKey, el] of pane.nodes) { el.classList.toggle('sg-selected', nodeKey === key); el.setAttribute('tabindex', nodeKey === key ? '0' : '-1'); }
            if (notify && typeof options.onSelect === 'function') options.onSelect(key);
        }
        function pane(graph, phase) {
            const repaired = phase === 'after', box = text('section', null, 'sg-pane'); box.dataset.graphPhase = phase; grid.append(box);
            const heading = text('div', null, 'sg-pane-heading');
            heading.append(text('h4', repaired ? 'После исправления' : (failures.length || after ? 'До исправления' : 'Полный граф')));
            const summary = graph.summary || {}, count = graph.nodes.length;
            heading.append(text('span', `${count} узлов · ${summary.structural_edges || 0} исходных связей`, 'sg-count'));
            if (!compact) box.append(heading);
            if (!compact && repaired) {
                const remaining = (graph.findings || []).filter(f => ['UNKNOWN', 'NOT_CHECKED', 'REQUIRES_EVIDENCE'].includes(f.status)).length;
                const resolved = failures.filter(f => afterById.get(f.id)?.status === 'PASS').length;
                box.append(text('p', `Результат проверки: устранено нарушений — ${resolved}.${remaining ? ` Остались неизвестные или непроверенные требования: ${remaining}.` : ''}`, 'sg-after-note'));
            } else if (!compact) box.append(text('p', `Пользователей с доказанным запрещённым доступом: ${summary.violators?.length || 0}${summary.absent_count ? ` · отсутствует компонентов: ${summary.absent_count}` : ''}`, 'sg-pane-note'));
            const tools = text('div', null, 'sg-pane-tools');
            const plus = button('+', () => zoom(.75)); plus.setAttribute('aria-label', 'Увеличить граф');
            const minus = button('−', () => zoom(1.33)); minus.setAttribute('aria-label', 'Уменьшить граф');
            const expand = button('На весь экран', () => { box.classList.toggle('sg-expanded'); expand.textContent = box.classList.contains('sg-expanded') ? 'Свернуть' : 'На весь экран'; });
            tools.append(plus, minus, button('Вписать', () => changeView(fullView())), expand); if (!compact) box.append(tools);
            if (graph.boundary && (graph.boundary.channels || graph.boundary.edges)) { const notice = text('p', `За границы этого кластера: каналов F/L/S — ${graph.boundary.channels}, исходных связей — ${graph.boundary.edges}. Внутри показаны только его компоненты. `, 'sg-boundary-note'); notice.append(button('Показать связи между кластерами', () => setView('clusters'))); box.append(notice); }
            if (selectedView === 'clusters') box.append(text('p', 'Одна вершина — один кластер. Стрелки объединяют только межкластерные каналы; внутренние связи видны внутри кластера. Нажмите вершину, чтобы открыть компоненты.', 'sg-boundary-note'));
            const canvas = svg('svg', {class: 'sg-canvas', viewBox: `0 0 ${layout.width} ${layout.height}`, 'aria-label': repaired ? 'Полный граф после исправления' : 'Полный граф до исправления', role: 'group'});
            box.append(canvas);
            const defs = svg('defs'); canvas.append(defs);
            for (const [kind, color] of [['plain', '#8d9bad'], ['risk', '#d52d42'], ['fixed', '#208458'], ['semantic', '#6a90a9'], ...Object.entries(LAYERS).map(([key, value]) => ['layer-' + key, value.color])]) {
                const marker = svg('marker', {id: `sg-${id}-${phase}-${kind}`, markerWidth: 7, markerHeight: 7, refX: kind.startsWith('layer-') ? 0 : 18, refY: 3.5, orient: 'auto', markerUnits: 'userSpaceOnUse'});
                marker.append(svg('path', {d: 'M0 0L7 3.5L0 7z', fill: color})); defs.append(marker);
            }
            const backdrop = svg('g'); canvas.append(backdrop);
            for (const group of layout.boxes) {
                backdrop.append(svg('rect', {x: group.x, y: group.y, width: group.width, height: group.height, rx: 20, class: 'sg-group-box'}));
                const label = svg('text', {x: group.x + 25, y: group.y + 36, class: 'sg-group-title'}); label.textContent = `${group.name} · ${group.count}`; backdrop.append(label);
            }
            const edgeLayer = svg('g', {class: 'sg-edge-layer'}); canvas.append(edgeLayer);
            const edges = [...(showLegacy ? graph.edges || [] : [])].sort((a, b) => Number(a.kind !== 'structural') - Number(b.kind !== 'structural') || Number(Boolean(a.witness)) - Number(Boolean(b.witness)));
            for (const edge of edges) {
                const a = layout.positions.get(edge.source), b = layout.positions.get(edge.target); if (!a || !b) continue;
                const fixed = repaired && ['access', 'flow'].includes(edge.kind) && edge.value === 'FALSE' && beforeEdges.get(edge.id)?.value === 'TRUE';
                const risk = edge.witness && edge.value === 'TRUE';
                const classes = ['sg-edge', hasLayers ? 'sg-layer-background' : '', edge.kind === 'structural' ? 'sg-structural' : 'sg-semantic', risk ? 'sg-risk-path' : '', fixed ? 'sg-blocked-path' : '', edge.value === 'UNKNOWN' ? 'sg-uncertain-edge' : '', edge.value === 'FALSE' && !fixed ? 'sg-inactive-edge' : ''];
                let d;
                if (edge.source === edge.target) d = `M ${a.x} ${a.y} C ${a.x - 65} ${a.y - 90} ${a.x + 65} ${a.y - 90} ${a.x} ${a.y}`;
                else {
                    const bend = edge.kind === 'structural' ? 10 : -24;
                    const dx = b.x - a.x, dy = b.y - a.y, length = Math.hypot(dx, dy) || 1;
                    d = `M${a.x},${a.y} Q${(a.x + b.x) / 2 - dy / length * bend},${(a.y + b.y) / 2 + dx / length * bend} ${b.x},${b.y}`;
                }
                const path = svg('path', {d, class: classes.join(' '), 'data-edge-id': edge.id, 'data-edge-kind': edge.kind, 'data-value': edge.value, 'data-witness': String(Boolean(risk)), 'data-blocked-change': String(Boolean(fixed)), 'marker-end': `url(#sg-${id}-${phase}-${hasLayers ? 'plain' : fixed ? 'fixed' : risk ? 'risk' : edge.kind === 'structural' ? 'plain' : 'semantic'})`});
                const title = svg('title'); title.textContent = `${edge.label || edge.kind}: ${edge.source} → ${edge.target}${edge.value === 'FALSE' ? ' · не действует' : ''}`; path.append(title); edgeLayer.append(path);
            }
            const layerEdges = (graph.layer_edges || []).filter(edge => LAYERS[edge.layer]);
            const lanes = new Map(), laneNumbers = new Map();
            const localNodes = new Map(graph.nodes.map(node => [node.key, node]));
            const nodeRadius = node => !node ? 13 : node.aggregateCluster != null ? 31 : node.is_violator || repaired && actor(node) && cleared.has(node.key) ? 24 : actor(node) ? 20 : 13;
            for (const edge of [...layerEdges].sort((a, b) => compare(a.channel_id || a.id, b.channel_id || b.id) || Object.keys(LAYERS).indexOf(a.layer) - Object.keys(LAYERS).indexOf(b.layer))) { const key = JSON.stringify([edge.source, edge.target]); if (!lanes.has(key)) lanes.set(key, []); laneNumbers.set(edge, lanes.get(key).length); lanes.get(key).push(edge); }
            for (const edge of layerEdges) {
                const a = layout.positions.get(edge.source), b = layout.positions.get(edge.target); if (!a || !b) continue;
                const lane = laneNumbers.get(edge), bend = 24 + lane * 22;
                const dx = b.x - a.x, dy = b.y - a.y, length = Math.hypot(dx, dy) || 1;
                const cx = (a.x + b.x) / 2 - dy / length * bend, cy = (a.y + b.y) / 2 + dx / length * bend;
                const sourceRadius = nodeRadius(localNodes.get(edge.source)), targetRadius = nodeRadius(localNodes.get(edge.target));
                const port = (Object.keys(LAYERS).indexOf(edge.layer) - 1) * 8;
                const start = {x: a.x + dx / length * (sourceRadius + 1) - dy / length * port, y: a.y + dy / length * (sourceRadius + 1) + dx / length * port};
                const end = {x: b.x - dx / length * (targetRadius + 9) - dy / length * port, y: b.y - dy / length * (targetRadius + 9) + dx / length * port};
                const d = edge.source === edge.target ? `M${a.x - sourceRadius * .6},${a.y - sourceRadius * .8} C${a.x - 65 - bend},${a.y - 100 - bend} ${a.x + 65 + bend},${a.y - 100 - bend} ${a.x + targetRadius * .6},${a.y - targetRadius * .8 - 9}` : `M${start.x},${start.y} Q${cx},${cy} ${end.x},${end.y}`;
                const protectedRoute = edge.via_protection === true;
                const path = svg('path', {d, class: `sg-edge sg-layer-edge sg-layer-${edge.layer}${protectedRoute ? ' sg-layer-protected' : ''}${edge.value === 'UNKNOWN' ? ' sg-layer-unknown' : ''}${edge.value === 'FALSE' ? ' sg-layer-inactive' : ''}${edge.witness ? ' sg-layer-risk' : ''}`, 'data-edge-id': edge.id, 'data-channel-id': edge.channel_id || edge.id, 'data-edge-kind': 'layer', 'data-layer': edge.layer, 'data-source': edge.source, 'data-target': edge.target, 'data-value': edge.value, 'data-via-protection': String(protectedRoute), 'marker-end': `url(#sg-${id}-${phase}-layer-${edge.layer})`});
                const title = svg('title'); title.textContent = `${LAYERS[edge.layer].name}: ${edge.source} → ${edge.target} · ${yesno(edge.value)}${protectedRoute ? ' · через защиту: ' + (edge.protection_via || []).join(', ') : ''}${edge.aggregate ? ' · каналов: ' + edge.channel_count + ' (1: ' + edge.values.TRUE + ', 0: ' + edge.values.FALSE + ', ?: ' + edge.values.UNKNOWN + '); через защиту: ' + edge.protected_count : ''}`; path.append(title); edgeLayer.append(path);
                const valueLabel = edge.aggregate ? String(edge.channel_count) + '×' + ({TRUE: '1', FALSE: '0', UNKNOWN: '?'}[edge.value] || '?') : edge.value === 'UNKNOWN' ? '?' : edge.value === 'FALSE' ? '0' : '';
                if (valueLabel) { const label = svg('text', {x: edge.source === edge.target ? a.x : (a.x + 2 * cx + b.x) / 4, y: edge.source === edge.target ? a.y - 80 - bend : (a.y + 2 * cy + b.y) / 4 - 4, class: 'sg-layer-value', 'data-layer': edge.layer}); label.textContent = valueLabel; edgeLayer.append(label); }
            }
            const elements = new Map(), nodeLayer = svg('g', {class: 'sg-node-layer'}); canvas.append(nodeLayer);
            for (const n of graph.nodes) {
                const point = layout.positions.get(n.key), fixed = repaired && !n.is_violator && (cleared.has(n.key) || n.changed && !trouble(n) && !uncertain(n));
                const cls = ['sg-node', actor(n) ? 'sg-actor' : '', n.is_violator ? 'sg-violator' : '', fixed ? 'sg-fixed' : '', !n.is_violator && (trouble(n) || uncertain(n)) ? 'sg-warning' : '', n.present === 'FALSE' ? 'sg-absent' : ''].join(' ');
                const item = svg('g', {class: cls, transform: `translate(${point.x},${point.y})`, 'data-node-key': n.key, 'data-violator': String(Boolean(n.is_violator)), 'data-present': n.present, 'data-fixed': String(Boolean(fixed)), role: 'button', tabindex: elements.size ? -1 : 0, 'aria-label': `${n.name}, ${n.pc || 'общий ресурс'}${n.is_violator ? ', запрещённый доступ' : ''}`});
                item.append(svg('circle', {r: n.aggregateCluster != null ? 31 : n.is_violator || fixed && actor(n) ? 24 : actor(n) ? 20 : 13, class: 'sg-node-shape'}));
                if (actor(n)) { item.append(svg('circle', {cx: 0, cy: -5, r: 5, class: 'sg-person'})); item.append(svg('path', {d: 'M-9 10 Q-9 0 0 0 Q9 0 9 10 Z', class: 'sg-person'})); }
                const label = svg('text', {y: actor(n) ? 39 : 31, 'text-anchor': 'middle', class: 'sg-node-label'});
                const name = n.name || n.key; const lines = name.match(/.{1,22}(?:\s|$)|.{1,22}/g) || [name];
                for (const [i, line] of lines.slice(0, 2).entries()) { const span = svg('tspan', {x: 0, dy: i ? 16 : 0}); span.textContent = line.trim() + (i === 1 && lines.length > 2 ? '…' : ''); label.append(span); }
                const title = svg('title'); title.textContent = `${n.name} · ${n.pc || 'Общий'} · ${n.key}`;
                if (n.aggregateCluster != null) { const countLabel = svg('text', {y: 58, 'text-anchor': 'middle', class: 'sg-cluster-count'}); countLabel.textContent = `${n.memberCount} компонентов`; item.append(countLabel); item.dataset.clusterId = n.aggregateCluster; }
                item.append(label, title); nodeLayer.append(item); elements.set(n.key, item);
                item.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); inspect(n.key); } });
            }
            panes.push({svg: canvas, nodes: elements, box, phase});
            let drag = null;
            function world(e) { const point = new DOMPoint(e.clientX, e.clientY); return point.matrixTransform(canvas.getScreenCTM().inverse()); }
            canvas.addEventListener('pointerdown', e => { if (e.button !== 0) return; const p = world(e); drag = {x: e.clientX, y: e.clientY, point: p, start: {...view}, key: e.target.closest('[data-node-key]')?.dataset.nodeKey}; canvas.setPointerCapture(e.pointerId); });
            canvas.addEventListener('pointermove', e => {
                if (!drag) return;
                const rect = canvas.getBoundingClientRect(), scale = Math.min(rect.width / drag.start.width, rect.height / drag.start.height);
                changeView({...drag.start, x: drag.start.x - (e.clientX - drag.x) / scale, y: drag.start.y - (e.clientY - drag.y) / scale});
            });
            const release = e => { if (drag?.key && Math.hypot(e.clientX - drag.x, e.clientY - drag.y) < 5) inspect(drag.key); drag = null; };
            canvas.addEventListener('pointerup', release); canvas.addEventListener('pointercancel', () => { drag = null; });
            canvas.addEventListener('wheel', e => { e.preventDefault(); const p = world(e), factor = e.deltaY > 0 ? 1.15 : .87, w = view.width * factor; if (w < layout.width / 14 || w > layout.width * 2) return; changeView({x: p.x - (p.x - view.x) * factor, y: p.y - (p.y - view.y) * factor, width: w, height: view.height * factor}); }, {passive: false});
            for (const diagnostic of graph.diagnostics || []) box.append(text('p', diagnostic.message || diagnostic.code, 'sg-diagnostic'));
            return box;
        }
        if (!compact && report.repair?.selected?.length && after) { const changes = text('section', null, 'sg-changes'); changes.append(text('h4', 'Что изменилось')); const list = text('ul'); for (const action of report.repair.selected) list.append(text('li', actionNames[action] || `Применено действие «${action}»`)); changes.append(list); root.append(changes); }
        const escape = e => { if (e.key === 'Escape') for (const expanded of root.querySelectorAll('.sg-expanded')) { expanded.classList.remove('sg-expanded'); const b = [...expanded.querySelectorAll('button')].find(x => x.textContent === 'Свернуть'); if (b) b.textContent = 'На весь экран'; } };
        document.addEventListener('keydown', escape); cleanups.push(() => document.removeEventListener('keydown', escape));
        setView(selectedView);
        return {setPhase, focusNodes: focusKeys, focusProblem, getView: () => selectedView, setView, getViewState, destroy() { for (const cleanup of cleanups) cleanup(); root.remove(); }};
    }
    window.SecurityGraphComparison = {mount};
})();
