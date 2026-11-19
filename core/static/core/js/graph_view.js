/* Complete graph rendering. Security decisions come from the analyzer payload. */
(() => {
    'use strict';
    const SVG = 'http://www.w3.org/2000/svg';
    let instance = 0;
    const text = (tag, value, cls) => { const e = document.createElement(tag); if (value != null) e.textContent = value; if (cls) e.className = cls; return e; };
    const svg = (tag, attrs = {}) => { const e = document.createElementNS(SVG, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v)); return e; };
    const compare = (a, b) => a.localeCompare(b, 'ru', {numeric: true});
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
    function arrange(graphs, compact = false) {
        const all = new Map();
        for (const g of graphs) for (const n of g.nodes || []) if (!all.has(n.key)) all.set(n.key, n);
        const groups = new Map();
        for (const n of all.values()) { const key = n.pc || 'Общие ресурсы'; if (!groups.has(key)) groups.set(key, []); groups.get(key).push(n); }
        const positions = new Map(), boxes = [];
        const locals = [...groups.keys()].filter(k => k !== 'Общие ресурсы').sort(compare);
        const order = [...locals, ...(groups.has('Общие ресурсы') ? ['Общие ресурсы'] : [])];
        const large = all.size > 40, width = compact && large ? 2720 : large ? 1900 : 1000;
        let y = 40;
        let rowBottom = y;
        for (let i = 0; i < order.length; i++) {
            const name = order[i], ns = groups.get(name).sort((a, b) => Number(actor(b)) - Number(actor(a)) || compare(a.key, b.key));
            const shared = name === 'Общие ресурсы';
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
            boxes.push({x, y, width: blockW, height: blockH, name, count: ns.length});
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
        if (!beforeState) { container.append(text('p', 'Нет состояния для построения графа.', 'sg-note')); return {setPhase() { return 'before'; }, focusNodes() {}, focusProblem() {}, destroy() { container.replaceChildren(); }}; }
        const before = beforeState.graph || fallback(beforeState), afterState = states.repaired, after = afterState?.graph || (afterState ? fallback(afterState) : null);
        const layout = arrange([before, ...(after ? [after] : [])], compact);
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
        const legend = text('div', null, 'sg-legend');
        for (const [cls, label] of [['violator', 'Пользователь с запрещённым доступом'], ['normal', 'Компонент'], ['warning', 'Проблема или неизвестность'], ['fixed', 'Исправлено'], ['blocked', 'Доступ перекрыт']]) {
            const item = text('span'); item.append(text('i', null, `sg-key sg-key-${cls}`), text('span', label)); legend.append(item);
        }
        if (!compact) {
            root.append(legend);
            root.append(text('p', 'Серые линии — исходные связи, красный путь — доказанный запрещённый доступ. Масштаб: колесо или кнопки. Перемещение: перетаскивание. Нажмите узел для объяснения.', 'sg-hint'));
        }
        const grid = text('div', null, `sg-grid ${compact || !failures.length && !after && !report.repair ? 'sg-single' : ''}`); root.append(grid);
        const inspector = text('aside', null, 'sg-inspector'); inspector.setAttribute('aria-live', 'polite');
        inspector.hidden = compact;
        if (!compact) inspector.append(text('strong', 'Выберите узел на графе'), text('p', 'Здесь появятся его название, состояние, связанные нарушения и изменения.'));
        root.append(inspector);
        let view = fullView(), selectedKey = null;
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
            if (selectedKey) inspect(selectedKey, false);
            return activePhase;
        }
        function focusKeys(keys) {
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
            const matches = [...layout.nodes.values()].filter(n => `${n.key} ${n.name} ${n.pc || ''}`.toLocaleLowerCase('ru').includes(query));
            if (!matches.length) { found.append(text('p', 'Компонент не найден.')); return; }
            for (const n of matches.slice(0, 12)) found.append(button(`${n.name} · ${n.pc || 'Общий'} · ${n.key}`, () => { focusKeys([n.key]); inspect(n.key); found.hidden = true; }));
            if (matches.length > 12) found.append(text('p', `Найдено ${matches.length}. Уточните название.`));
            if (matches.length === 1) { focusKeys([matches[0].key]); inspect(matches[0].key); }
        }
        search.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); searchNodes(); } });
        function inspect(key, notify = true) {
            selectedKey = key; inspector.replaceChildren();
            const n = layout.nodes.get(key); if (!n) return;
            inspector.hidden = false;
            inspector.append(text('h4', `${n.name} · ${n.pc || 'Общие ресурсы'}`));
            if (!compact) inspector.append(text('span', key, 'sg-node-id'));
            const columns = text('div', null, 'sg-inspector-columns');
            const snapshots = compact ? [[activePhase === 'after' ? after : before, '']] : [[before, after ? 'До исправления' : 'Текущее состояние'], ...(after ? [[after, 'После исправления']] : [])];
            for (const [g, title] of snapshots) {
                const current = g.nodes.find(item => item.key === key); if (!current) continue;
                const cell = text('div'); if (title) cell.append(text('strong', title));
                const status = current.is_violator ? 'Доказан запрещённый доступ' : g === after && cleared.has(key) ? 'Запрещённый доступ устранён' : trouble(current) ? 'Связан с нарушением требования' : uncertain(current) ? 'Есть неизвестные условия' : 'Доказанный запрещённый доступ не найден';
                cell.append(text('p', status));
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
            const canvas = svg('svg', {class: 'sg-canvas', viewBox: `0 0 ${layout.width} ${layout.height}`, 'aria-label': repaired ? 'Полный граф после исправления' : 'Полный граф до исправления', role: 'group'});
            box.append(canvas);
            const defs = svg('defs'); canvas.append(defs);
            for (const [kind, color] of [['plain', '#8d9bad'], ['risk', '#d52d42'], ['fixed', '#208458'], ['semantic', '#6a90a9']]) {
                const marker = svg('marker', {id: `sg-${id}-${phase}-${kind}`, markerWidth: 7, markerHeight: 7, refX: 18, refY: 3.5, orient: 'auto', markerUnits: 'userSpaceOnUse'});
                marker.append(svg('path', {d: 'M0 0L7 3.5L0 7z', fill: color})); defs.append(marker);
            }
            const backdrop = svg('g'); canvas.append(backdrop);
            for (const group of layout.boxes) {
                backdrop.append(svg('rect', {x: group.x, y: group.y, width: group.width, height: group.height, rx: 20, class: 'sg-group-box'}));
                const label = svg('text', {x: group.x + 25, y: group.y + 36, class: 'sg-group-title'}); label.textContent = `${group.name} · ${group.count}`; backdrop.append(label);
            }
            const edgeLayer = svg('g', {class: 'sg-edge-layer'}); canvas.append(edgeLayer);
            const edges = [...(graph.edges || [])].sort((a, b) => Number(a.kind !== 'structural') - Number(b.kind !== 'structural') || Number(Boolean(a.witness)) - Number(Boolean(b.witness)));
            for (const edge of edges) {
                const a = layout.positions.get(edge.source), b = layout.positions.get(edge.target); if (!a || !b) continue;
                const fixed = repaired && ['access', 'flow'].includes(edge.kind) && edge.value === 'FALSE' && beforeEdges.get(edge.id)?.value === 'TRUE';
                const risk = edge.witness && edge.value === 'TRUE';
                const classes = ['sg-edge', edge.kind === 'structural' ? 'sg-structural' : 'sg-semantic', risk ? 'sg-risk-path' : '', fixed ? 'sg-blocked-path' : '', edge.value === 'UNKNOWN' ? 'sg-uncertain-edge' : '', edge.value === 'FALSE' && !fixed ? 'sg-inactive-edge' : ''];
                let d;
                if (edge.source === edge.target) d = `M ${a.x} ${a.y} C ${a.x - 65} ${a.y - 90} ${a.x + 65} ${a.y - 90} ${a.x} ${a.y}`;
                else {
                    const bend = edge.kind === 'structural' ? 10 : -24;
                    const dx = b.x - a.x, dy = b.y - a.y, length = Math.hypot(dx, dy) || 1;
                    d = `M${a.x},${a.y} Q${(a.x + b.x) / 2 - dy / length * bend},${(a.y + b.y) / 2 + dx / length * bend} ${b.x},${b.y}`;
                }
                const path = svg('path', {d, class: classes.join(' '), 'data-edge-id': edge.id, 'data-edge-kind': edge.kind, 'data-value': edge.value, 'data-witness': String(Boolean(risk)), 'data-blocked-change': String(Boolean(fixed)), 'marker-end': `url(#sg-${id}-${phase}-${fixed ? 'fixed' : risk ? 'risk' : edge.kind === 'structural' ? 'plain' : 'semantic'})`});
                const title = svg('title'); title.textContent = `${edge.label || edge.kind}: ${edge.source} → ${edge.target}${edge.value === 'FALSE' ? ' · не действует' : ''}`; path.append(title); edgeLayer.append(path);
            }
            const elements = new Map(), nodeLayer = svg('g', {class: 'sg-node-layer'}); canvas.append(nodeLayer);
            for (const n of graph.nodes) {
                const point = layout.positions.get(n.key), fixed = repaired && !n.is_violator && (cleared.has(n.key) || n.changed && !trouble(n) && !uncertain(n));
                const cls = ['sg-node', actor(n) ? 'sg-actor' : '', n.is_violator ? 'sg-violator' : '', fixed ? 'sg-fixed' : '', !n.is_violator && (trouble(n) || uncertain(n)) ? 'sg-warning' : '', n.present === 'FALSE' ? 'sg-absent' : ''].join(' ');
                const item = svg('g', {class: cls, transform: `translate(${point.x},${point.y})`, 'data-node-key': n.key, 'data-violator': String(Boolean(n.is_violator)), 'data-present': n.present, 'data-fixed': String(Boolean(fixed)), role: 'button', tabindex: elements.size ? -1 : 0, 'aria-label': `${n.name}, ${n.pc || 'общий ресурс'}${n.is_violator ? ', запрещённый доступ' : ''}`});
                item.append(svg('circle', {r: n.is_violator || fixed && actor(n) ? 24 : actor(n) ? 20 : 13, class: 'sg-node-shape'}));
                if (actor(n)) { item.append(svg('circle', {cx: 0, cy: -5, r: 5, class: 'sg-person'})); item.append(svg('path', {d: 'M-9 10 Q-9 0 0 0 Q9 0 9 10 Z', class: 'sg-person'})); }
                const label = svg('text', {y: actor(n) ? 39 : 31, 'text-anchor': 'middle', class: 'sg-node-label'});
                const name = n.name || n.key; const lines = name.match(/.{1,22}(?:\s|$)|.{1,22}/g) || [name];
                for (const [i, line] of lines.slice(0, 2).entries()) { const span = svg('tspan', {x: 0, dy: i ? 16 : 0}); span.textContent = line.trim() + (i === 1 && lines.length > 2 ? '…' : ''); label.append(span); }
                const title = svg('title'); title.textContent = `${n.name} · ${n.pc || 'Общий'} · ${n.key}`;
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
        pane(before, 'before');
        if (after) pane(after, 'after');
        else if (!compact && (failures.length || report.repair)) {
            const placeholder = text('section', null, 'sg-pane sg-placeholder'); placeholder.dataset.graphPhase = 'after';
            placeholder.append(text('h4', 'После исправления'), text('p', report.repair ? `Проверенного исправления пока нет. ${report.repair.status === 'NO_TARGET_VIOLATIONS' ? 'Неизвестные условия нельзя считать устранёнными нарушениями.' : 'Поиск не дал подтверждённого результата в заданных ограничениях.'}` : 'Здесь появится второй полный граф после применения и проверки исправления.'));
            if (options.onRepair) {
                const repairButton = button('Устранить уязвимость', async () => { repairButton.disabled = true; repairButton.textContent = 'Проверяем исправление…'; try { await options.onRepair(); } catch (error) { placeholder.append(text('p', error.message || 'Не удалось выполнить исправление.', 'sg-diagnostic')); repairButton.disabled = false; repairButton.textContent = 'Повторить исправление'; } }, 'sg-primary');
                repairButton.dataset.repairGraph = 'true'; repairButton.disabled = Boolean(options.busy); placeholder.append(repairButton);
            } else placeholder.append(text('p', options.busy ? 'Дождитесь окончания текущей проверки.' : 'Для этой модели не задан доступный каталог исправлений.', 'sg-note'));
            grid.append(placeholder);
        }
        if (!compact && report.repair?.selected?.length && after) { const changes = text('section', null, 'sg-changes'); changes.append(text('h4', 'Что изменилось')); const list = text('ul'); for (const action of report.repair.selected) list.append(text('li', actionNames[action] || `Применено действие «${action}»`)); changes.append(list); root.append(changes); }
        const escape = e => { if (e.key === 'Escape') for (const expanded of root.querySelectorAll('.sg-expanded')) { expanded.classList.remove('sg-expanded'); const b = [...expanded.querySelectorAll('button')].find(x => x.textContent === 'Свернуть'); if (b) b.textContent = 'На весь экран'; } };
        document.addEventListener('keydown', escape); cleanups.push(() => document.removeEventListener('keydown', escape));
        changeView(view);
        setPhase(activePhase);
        return {setPhase, focusNodes: focusKeys, focusProblem, destroy() { for (const cleanup of cleanups) cleanup(); root.remove(); }};
    }
    window.SecurityGraphComparison = {mount};
})();
