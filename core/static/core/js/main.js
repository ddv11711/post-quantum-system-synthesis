/* One graph workspace for uploaded semantic models and verified repairs. */
(() => {
    'use strict';
    const $ = id => document.getElementById(id);
    const app = $('security-app');
    if (!app) return;

    // Consume the File selected on the landing page. The file is removed
    // from IndexedDB after it is read; execute() retains it for Retry.
    function takePendingImport() {
        return new Promise((resolve, reject) => {
            if (!window.indexedDB) {
                reject(new Error('Хранилище IndexedDB недоступно в этом браузере.'));
                return;
            }
            const request = indexedDB.open('bigvizov-import-files', 1);
            request.onupgradeneeded = () => {
                const db = request.result;
                if (!db.objectStoreNames.contains('uploads')) db.createObjectStore('uploads');
            };
            request.onerror = () => reject(request.error || new Error('Не удалось открыть хранилище файла.'));
            request.onblocked = () => reject(new Error('Хранилище файла занято другой вкладкой.'));
            request.onsuccess = () => {
                const db = request.result;
                const tx = db.transaction('uploads', 'readwrite');
                let file;
                const get = tx.objectStore('uploads').get('pending');
                get.onsuccess = () => {
                    file = get.result;
                    tx.objectStore('uploads').delete('pending');
                };
                tx.oncomplete = () => { db.close(); resolve(file); };
                tx.onerror = () => { db.close(); reject(tx.error || new Error('Не удалось прочитать файл.')); };
                tx.onabort = () => { db.close(); reject(tx.error || new Error('Чтение файла прервано.')); };
            };
        });
    }

    let report = null, graphView = null, phase = 'before', busy = false, exportBusy = false, lastLoad = {kind: 'upload', file: null};
    let cachedRepairSource = null;
    function repairSourceFile() {
        if (lastLoad.file && /\.xlsx$/i.test(lastLoad.file.name || '')) return lastLoad.file;
        if (cachedRepairSource) return cachedRepairSource;
        const stored = $('initial-repair-source');
        if (!stored) return null;
        const {filename, content} = JSON.parse(stored.textContent);
        if (!/\.xlsx$/i.test(filename) || typeof content !== 'string') return null;
        const binary = atob(content);
        const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
        cachedRepairSource = new File([bytes], filename,
            {type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
        return cachedRepairSource;
    }
    const icons = {
        warning: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3 3 7v6c0 5 9 8 9 8s9-3 9-8V7l-9-4Z" stroke="currentColor" stroke-width="1.7"/><path d="M12 8v5m0 3v.1" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        success: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3 3 7v6c0 5 9 8 9 8s9-3 9-8V7l-9-4Z" stroke="currentColor" stroke-width="1.7"/><path d="m8 12 3 3 5-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>'
    };
    function el(tag, value, cls) { const n = document.createElement(tag); if (value != null) n.textContent = value; if (cls) n.className = cls; return n; }
    function state(name = phase) { return report?.states?.[name === 'after' ? 'repaired' : name]; }
    function results(snapshot) { return snapshot?.analysis?.results || []; }
    function summary(snapshot) {
        const items = results(snapshot), statuses = items.map(r => r.status);
        return {total: items.length, pass: statuses.filter(s => s === 'PASS').length, fail: statuses.filter(s => s === 'FAIL').length,
            unknown: statuses.filter(s => ['UNKNOWN', 'NOT_CHECKED', 'REQUIRES_EVIDENCE'].includes(s)).length,
            errors: (snapshot?.analysis?.model_errors || []).length,
            applicable: items.filter(r => r.status !== 'NOT_APPLICABLE' && r.checker !== 'semantic_readiness').length};
    }
    function feedback(message) { $('page-feedback').textContent = message; $('page-feedback').hidden = !message; }
    function retryLoad() {
        if (lastLoad.kind === 'upload' && !lastLoad.file) {
            window.location.href = '/';
            return;
        }
        execute(lastLoad.kind, lastLoad.file);
    }
    function showLoadError(message, filename = '') {
        graphView?.destroy(); graphView = null; report = null; phase = 'before';
        const loading = el('div', null, 'graph-loading');
        const caption = el('p', 'Граф не загружен'); caption.id = 'loading-message';
        const retry = el('button', lastLoad.kind === 'upload' && !lastLoad.file ? 'Вернуться на главную' : 'Повторить загрузку', 'secondary-button');
        retry.id = 'retry-button'; retry.type = 'button'; retry.addEventListener('click', retryLoad);
        loading.append(caption, retry); $('security-graph').replaceChildren(loading);
        $('security-graph').setAttribute('aria-busy', 'false');
        $('system-status').dataset.state = 'warning'; $('status-symbol').innerHTML = icons.warning;
        $('status-title').textContent = 'Не удалось загрузить граф';
        $('status-description').textContent = 'Выберите исходный файл ещё раз. Результат анализа не сформирован.';
        $('node-count').textContent = '—'; $('edge-count').textContent = '—'; $('layer-count-note').hidden = true;
        $('check-count').textContent = 'Проверка не выполнена'; $('check-description').textContent = 'Сначала загрузите граф.';
        $('check-icon').textContent = '—'; $('check-icon').classList.remove('is-complete');
        $('findings-title').textContent = 'Результат проверки'; $('finding-count').hidden = true;
        $('findings-list').replaceChildren(el('p', 'Результат появится после загрузки файла.', 'findings-empty'));
        $('unknown-details').hidden = true; $('coverage-details').hidden = true; $('profile-details').hidden = true;
        $('before-tab').disabled = true; $('after-tab').disabled = true; $('repair-button').disabled = true;
        feedback(message);
    }
    function normalize(data) {
        const all = data.states || {};
        const key = ['before', 'experiment', 'uploaded', 'imported', 'changed', 'baseline'].find(k => all[k]) || Object.keys(all).find(k => k !== 'repaired');
        if (!key || !Array.isArray(all[key]?.graph?.nodes) || !Array.isArray(all[key]?.analysis?.results)) throw new Error('В ответе отсутствует граф и результаты анализа.');
        return {...data, states: {before: all[key], ...(all.repaired ? {repaired: all.repaired} : {})}};
    }
    function renderStatus() {
        const latest = state('repaired') || state('before'), s = summary(latest);
        const clean = s.applicable > 0 && !s.fail && !s.unknown && !s.errors;
        const saved = report?.display_mode === 'saved_report';
        const flowRepair = report?.repair_capability?.type === 'mandate_flow';
        const sourceAvailable = !!app.dataset.template || /\.xlsx$/i.test(lastLoad.file?.name || '') || !!$('initial-repair-source');
        const canRepair = !saved && (state('before')?.model?.action_catalog?.length > 0 ||
            Boolean(app.dataset.template && report?.scenario) || (flowRepair && sourceAvailable));
        let title, description;
        if (s.errors) { title = 'В описании модели есть ошибки'; description = 'Исправьте противоречия и ссылки в исходных данных. Заключение о безопасности не сформировано.'; }
        else if (!s.applicable) { title = 'Проверка безопасности не выполнена'; description = 'Граф построен, но нет применимых требований безопасности. По одним компонентам и связям определить нарушителей нельзя.'; }
        else if (s.fail) { title = `Найдено нарушений: ${s.fail}`; description = canRepair ? 'Можно подобрать исправления из разрешённых для этой модели действий.' : 'Нарушения показаны справа. Для автоматического исправления задайте разрешённые действия.'; }
        else if (s.unknown) {
            title = state('repaired') ? 'Подтверждённые нарушения устранены' : 'Не все требования удалось проверить';
            description = state('repaired')
                ? `Исправления повторно проверены. Условий, требующих дополнительных данных: ${s.unknown}.`
                : `Неизвестных или неподдержанных условий: ${s.unknown}. Нужны дополнительные данные.`;
        }
        else { title = state('repaired') ? 'Найденные нарушения устранены' : 'Заданные требования выполнены'; description = 'Вывод относится к описанным фактам и требованиям этой модели.'; }
        if (report?.repair && !state('repaired') && s.fail) description = repairReason(report.repair);
        if (saved) description = 'Сохранённый отчёт: результаты показаны без нового вычисления. Для новой проверки загрузите модель.';
        $('system-status').dataset.state = busy ? 'loading' : clean && !saved ? 'success' : 'warning';
        $('status-symbol').innerHTML = busy ? '<span class="spinner"></span>' : icons[clean && !saved ? 'success' : 'warning'];
        $('status-title').textContent = busy ? 'Выполняем проверку…' : title;
        $('status-description').textContent = busy ? 'Проверяем требования и сохраняем исходное состояние графа.' : description;
        $('repair-button').disabled = busy || saved || !s.fail || !!s.errors || !canRepair || !!state('repaired');
        $('repair-button').textContent = busy ? 'Проверяем…' : state('repaired') ? 'Исправления проверены' : report?.repair ? 'Повторить исправление' : 'Исправить нарушения';
        const exportButton = $('export-repaired-button');
        if (exportButton) {
            const canExport = !!state('repaired') && (!!app.dataset.template || !!repairSourceFile());
            exportButton.hidden = !canExport;
            exportButton.disabled = busy || exportBusy || !canExport;
            exportButton.classList.toggle('is-exporting', exportBusy);
            exportButton.setAttribute('aria-busy', String(exportBusy));
            exportButton.querySelector('.analysis-export-button-label').textContent = exportBusy ? 'Подготавливаем Excel' : 'Экспортировать Excel';
        }
        $('before-tab').disabled = busy || !report;
        $('after-tab').disabled = busy || !state('repaired');
        for (const button of app.querySelectorAll('[data-profile-id]')) button.disabled = busy || button.dataset.profileUnavailable === 'true';
    }
    function repairReason(repair) {
        return {NO_VALID_REPAIR_IN_ACTION_SPACE: 'Разрешённые действия не устраняют все нарушения с сохранением обязательных функций.', SEARCH_LIMIT: 'Достигнут предел поиска. Подтверждённое исправление не найдено.', NO_TARGET_VIOLATIONS: 'Подтверждённых нарушений для исправления нет. Неизвестные условия требуют новых данных.', MODEL_ERROR: 'Нельзя исправлять противоречивую модель.', VERIFICATION_FAILED: 'Повторная проверка не подтвердила исправление.'}[repair.status] || 'Подтверждённого исправления пока нет. Исходный граф сохранён.';
    }
    function findingCard(finding, fixed = false) {
        const card = el('button', null, `finding-card ${fixed ? 'is-fixed' : ''}`); card.type = 'button'; card.dataset.findingId = finding.id;
        const mark = el('span', fixed ? '✓' : finding.status === 'FAIL' ? '!' : '?', 'finding-mark'); mark.setAttribute('aria-hidden', 'true');
        const content = el('span', null, 'finding-content');
        const readiness = finding.checker === 'semantic_readiness';
        content.append(el('strong', readiness ? 'Полнота данных' : finding.name || finding.rule_id || finding.id), el('span', fixed ? 'После исправления требование выполнено.' : readiness ? 'Нужно уточнить условия проверки.' : finding.message || finding.reason || 'Нужны дополнительные сведения.'));
        const missing = finding.unknowns || [];
        if (!fixed && finding.status === 'UNKNOWN' && missing.length) content.append(el('small', (readiness ? '' : 'Нужно уточнить: ') + missing.slice(0, 4).map(x => readiness ? (x.args || []).join('; ') : `${x.predicate || x.field || 'условие'}${x.args?.length ? ' (' + x.args.join(', ') + ')' : ''}`).join('; ')));
        card.append(mark, content);
        card.addEventListener('click', () => {
            // Delegate focus to the graph: a mandate-flow violation can link
            // distant PCs, so fitting both ends would barely zoom on large graphs.
            graphView?.focusFinding(finding);
            if (window.matchMedia('(max-width:900px)').matches) $('security-graph').scrollIntoView({block: 'center', behavior: 'instant'});
        });
        return card;
    }
    function renderFindings() {
        const current = state(), s = summary(current), findings = current.graph.findings || [];
        const initial = state('before').graph.findings || [];
        const byId = new Map(findings.map(f => [f.id, f]));
        const failures = findings.filter(f => f.status === 'FAIL').sort((a, b) => Number(Boolean(b.offender)) - Number(Boolean(a.offender)));
        const visible = phase === 'after' ? initial.filter(f => f.status === 'FAIL').map(f => byId.get(f.id) || f) : failures;
        const list = $('findings-list'); list.replaceChildren();
        $('findings-title').textContent = !s.applicable || s.errors ? 'Результат проверки' : phase === 'after' ? 'Результат исправления' : state('repaired') ? 'До исправления' : 'Найденные нарушения';
        $('finding-count').hidden = !s.applicable || !!s.errors; $('finding-count').textContent = visible.length;
        $('finding-count').classList.toggle('is-fixed', phase === 'after' && !s.fail);
        for (const finding of visible) list.append(findingCard(finding, phase === 'after' && finding.status === 'PASS'));
        if (!visible.length) list.append(el('p', s.errors ? 'Проверки заблокированы ошибками модели.' : !s.applicable ? 'Защищённость не определена. Нужны правила доступа или требования к компонентам; список связей их не заменяет.' : s.unknown ? 'Подтверждённых нарушений нет, но часть проверок не завершена.' : 'Нарушений заданных требований не обнаружено.', 'findings-empty'));
        const profiles = (Array.isArray(report.available_profiles) ? report.available_profiles : []).filter(profile =>
            profile && ['id', 'name', 'description'].every(key => typeof profile[key] === 'string' && profile[key].trim()));
        for (const profile of profiles) {
            const card = el('div', null, 'profile-choice');
            card.append(el('strong', profile.name), el('p', profile.description));
            if (profile.can_apply === false) for (const diagnostic of Array.isArray(profile.diagnostics) ? profile.diagnostics : []) {
                if (diagnostic?.severity === 'error' && typeof diagnostic.message === 'string') card.append(el('p', diagnostic.message));
            }
            const apply = el('button', profile.id === 'mandate-flows-v1' ? 'Проверить мандатные потоки' : 'Проверить по профилю', 'secondary-button');
            apply.type = 'button'; apply.dataset.profileId = profile.id; apply.dataset.profileUnavailable = String(profile.can_apply === false);
            apply.disabled = busy || profile.can_apply === false;
            apply.addEventListener('click', () => execute('profile', null, profile)); card.append(apply); list.append(card);
        }
        const unknown = findings.filter(f => ['UNKNOWN', 'NOT_CHECKED', 'REQUIRES_EVIDENCE', 'MODEL_ERROR'].includes(f.status));
        const extra = current.scope?.warnings || [];
        $('unknown-details').hidden = !!s.applicable && !unknown.length && !s.errors && !extra.length;
        $('unknown-summary').textContent = s.errors ? `Ошибки модели: ${s.errors}` : !s.applicable ? 'Не хватает условий проверки' : unknown.length ? `Недостаточно данных: ${unknown.length}` : 'Ограничения проверки';
        const unknownList = $('unknown-list'); unknownList.replaceChildren();
        for (const finding of unknown) unknownList.append(findingCard(finding));
        for (const error of current.analysis.model_errors || []) unknownList.append(el('p', [error.code, error.path, error.object, error.id, error.reason].filter(Boolean).join(' · ')));
        for (const warning of extra) unknownList.append(el('p', warning));
        if (!s.applicable && !unknown.length && !extra.length && !s.errors) unknownList.append(el('p', 'Добавьте требования и факты для их проверки: например, кому разрешён доступ к ресурсу и какие операции разрешены.'));
        $('check-count').textContent = s.errors ? 'Проверка заблокирована' : !s.applicable ? 'Проверка не выполнена' : `${s.pass} из ${s.total} проверок пройдено`;
        $('check-icon').textContent = s.errors || !s.applicable ? '—' : s.unknown ? '?' : s.fail ? '!' : '✓';
        const profileCoverage = current.model?.profile_coverage;
        const flowGaps = profileCoverage && ['unchecked_flows', 'unresolved_references'].every(key => Number.isInteger(profileCoverage[key]) && profileCoverage[key] >= 0)
            ? `Связей без меток: ${profileCoverage.unchecked_flows}. Неоднозначных ссылок: ${profileCoverage.unresolved_references}.` : '';
        $('check-description').textContent = s.errors ? 'Вывод заблокирован ошибкой данных.' : s.unknown && flowGaps ? flowGaps : !s.applicable ? 'Отсутствие результатов не означает отсутствие уязвимостей.' : s.unknown ? `Требуют уточнения: ${s.unknown}.` : 'Оцениваются только требования этой модели.';
        $('check-icon').classList.toggle('is-complete', s.applicable > 0 && !s.fail && !s.unknown && !s.errors);
        $('before-tab').setAttribute('aria-pressed', String(phase === 'before')); $('after-tab').setAttribute('aria-pressed', String(phase === 'after'));
        $('node-count').textContent = current.graph.nodes.length;
        $('edge-count').textContent = new Intl.NumberFormat('ru-RU').format(current.graph.summary?.structural_edges || 0);
        $('layer-count-note').hidden = !current.graph.layer_edges?.length;
        $('layer-count').textContent = new Intl.NumberFormat('ru-RU').format(current.graph.layer_edges?.length || 0);
        $('coverage-details').hidden = !current.scope;
        const coverage = $('coverage-list'); coverage.replaceChildren();
        for (const family of current.scope?.families || []) coverage.append(el('p', `${family.name}: ${family.configured ? family.requirements + ' проверок' : 'требования не заданы'}`));
        if (current.scope) coverage.append(el('p', current.scope.statement));
        const activeProfile = report.profile || state('before')?.model?.detected_profile;
        const hasProfile = activeProfile && typeof activeProfile.name === 'string';
        $('profile-details').hidden = !hasProfile;
        $('active-profile-name').textContent = hasProfile ? activeProfile.name : '';
        const rules = $('profile-assumptions'); rules.replaceChildren();
        const assumptions = activeProfile?.assumptions || report.assumptions;
        for (const assumption of Array.isArray(assumptions) ? assumptions : []) {
            if (typeof assumption === 'string') rules.append(el('li', assumption));
        }
        if (hasProfile && !rules.children.length && typeof activeProfile.description === 'string') rules.append(el('li', activeProfile.description));
    }
    function setPhase(next) { if (busy || next === 'after' && !state('repaired')) return; phase = graphView.setPhase(next); renderFindings(); }
    function renderReport(data, repaired, preserveView = false) {
        const normalized = normalize(data);
        const viewState = repaired || preserveView ? graphView?.getViewState?.() : undefined;
        report = normalized; graphView?.destroy(); phase = repaired && state('repaired') ? 'after' : 'before';
        graphView = window.SecurityGraphComparison.mount($('security-graph'), report, {compact: true, phase, beforeState: 'before', viewState});
        $('security-graph').setAttribute('aria-busy', 'false');
        renderFindings();
    }
    async function execute(kind, file, profile) {
        if (busy) return;
        if (kind !== 'repair' && kind !== 'profile') lastLoad = {kind, file};
        busy = true; feedback('');
        if (report) renderStatus();
        else {
            $('retry-button').hidden = true;
            $('loading-message').textContent = 'Загружаем и проверяем граф';
            $('system-status').dataset.state = 'loading'; $('status-symbol').innerHTML = '<span class="spinner"></span>';
            $('status-title').textContent = 'Загружаем граф…'; $('status-description').textContent = 'Проверяем выбранные данные.';
        }
        if (kind !== 'repair') {
            window.AnalysisLoading?.show(kind === 'profile' ? 'Применяем профиль…' : 'Анализируем систему…');
        }
        const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), kind === 'repair' ? 120000 : 60000);
        try {
            const headers = {'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value};
            let url = app.dataset.uploadUrl, body;
            if (kind === 'upload') { if (!file) throw new Error('Выберите файл графа.'); url = app.dataset.uploadUrl; body = new FormData(); body.append('file', file); }
            else if (kind === 'profile') {
                const graph = state('before')?.model?.source_graph;
                if (!graph || !profile?.id) throw new Error('Для применения профиля нужен исходный граф. Загрузите файл ещё раз.');
                url = app.dataset.uploadUrl; body = new FormData();
                body.append('file', new Blob([JSON.stringify({kind: 'structural_profile', profile: profile.id, graph})], {type: 'application/json'}), 'structural-profile.json');
            }
            else if (kind === 'scenario') {
                if (!app.dataset.template) throw new Error('Выберите шаблон на главной странице.');
                url = app.dataset.scenarioUrl;
                headers['Content-Type'] = 'application/json';
                body = JSON.stringify({repair: false, template: app.dataset.template});
            }
            else if (kind === 'repair' && app.dataset.template &&
                     (report?.scenario || report?.repair_capability?.type === 'mandate_flow')) {
                url = app.dataset.scenarioUrl;
                headers['Content-Type'] = 'application/json';
                body = JSON.stringify({repair: true, template: app.dataset.template});
            }
            else if (kind === 'repair' && report?.repair_capability?.type === 'mandate_flow') {
                const source = repairSourceFile();
                if (!source) throw new Error('Исходный Excel не найден. Загрузите файл повторно.');
                url = app.dataset.repairUrl;
                body = new FormData();
                body.append('source_file', source, source.name);
            }
            else if (kind === 'repair') {
                const model = state('before')?.model;
                if (!model) throw new Error('Отчёт не содержит модель для исправления. Загрузите исходный файл.');
                url = app.dataset.repairUrl; body = new FormData(); body.append('file', new Blob([JSON.stringify({model})], {type: 'application/json'}), 'model.json');
            } else { throw new Error('Неизвестный режим анализа.'); }
            const response = await fetch(url, {method: 'POST', headers, body, signal: controller.signal});
            let data; try { data = await response.json(); } catch (_) { throw new Error('Некорректный ответ сервера. Проверьте формат и размер графа.'); }
            if (!response.ok) throw new Error(data.error || 'Не удалось проверить граф.');
            if (kind === 'scenario' && !data.filename) data.filename = app.dataset.template;
            if (kind === 'repair' || kind === 'profile') data.filename = report.filename;
            renderReport(data, kind === 'repair', kind === 'profile');
            if (kind === 'repair' && !state('repaired')) feedback(repairReason(data.repair || {}));
        } catch (error) {
            let message = error.name === 'AbortError' ? 'Превышено время обработки. Попробуйте уменьшить граф или использовать CLI.' : error.name === 'TypeError' ? 'Не удалось связаться с сервером.' : error.message;
            if (kind === 'upload' && report) message = `Файл «${file?.name || 'граф'}» не загружен. ${message} Сейчас показан предыдущий граф «${report.filename || 'без названия'}».`;
            if (kind === 'profile' && report) message = `Не удалось применить профиль. ${message} Показан исходный граф.`;
            if (!report) {
                showLoadError(message, file?.name || '');
            } else feedback(message);
        } finally {
            clearTimeout(timeout); busy = false;
            if (kind !== 'repair') window.AnalysisLoading?.hide();
            if (report) renderStatus();
        }
    }
    // Re-run verification on the server and export the original five-column XLSX.
    // Never send expanded graph JSON or client-chosen action IDs to the server.
    async function exportRepairedWorkbook() {
        if (busy || exportBusy || !state('repaired')) return;
        const source = app.dataset.template ? null : repairSourceFile();
        if (!app.dataset.template && !source) {
            feedback('Исходный XLSX недоступен для экспорта. Загрузите файл повторно.');
            return;
        }
        exportBusy = true;
        renderStatus();
        feedback('');
        // The export button itself displays progress; no full-page overlay.
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 180000);
        try {
            const body = new FormData();
            if (app.dataset.template) body.append('template', app.dataset.template);
            else body.append('source_file', source, source.name);
            const response = await fetch(app.dataset.exportUrl, {
                method: 'POST',
                headers: {'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value},
                body, signal: controller.signal
            });
            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.error || 'Не удалось экспортировать исправленный Excel.');
            }
            const payload = await response.blob();
            const disposition = response.headers.get('Content-Disposition') || '';
            let filename = 'Конфигурация_после_исправления.xlsx';
            const encodedName = disposition.match(/filename\*=UTF-8''([^;]+)/i);
            const plainName = disposition.match(/filename="([^"]+)"/i);
            if (encodedName) filename = decodeURIComponent(encodedName[1]);
            else if (plainName) filename = plainName[1];
            const url = URL.createObjectURL(payload);
            const link = document.createElement('a');
            link.href = url; link.download = filename; document.body.appendChild(link); link.click(); link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1500);
        } catch (error) {
            feedback(error.name === 'AbortError' ? 'Превышено время подготовки файла.' : error.message);
        } finally {
            clearTimeout(timeout);
            exportBusy = false;
            renderStatus();
        }
    }
    $('export-repaired-button')?.addEventListener('click', exportRepairedWorkbook);
    $('repair-button').addEventListener('click', () => execute('repair'));
    $('retry-button').addEventListener('click', retryLoad);
    $('before-tab').addEventListener('click', () => setPhase('before')); $('after-tab').addEventListener('click', () => setPhase('after'));
    const initialReport = $('initial-report'), initialError = $('initial-error');
    if (initialReport || initialError) {
        lastLoad = {kind: 'upload', file: null};
        let filename = '';
        try {
            if ($('initial-filename')) filename = JSON.parse($('initial-filename').textContent);
            if (initialReport) {
                renderReport(JSON.parse(initialReport.textContent), false);
                renderStatus();
            } else showLoadError(JSON.parse(initialError.textContent), filename);
        } catch (_) {
            showLoadError('Не удалось отобразить загруженный файл. Проверьте его формат и выберите файл заново.', filename);
        }
    } else if (app.dataset.uploadedMode === 'true') {
        // Retrieve the original File (usually a few KB), and use the same
        // upload endpoint as the analyzer's own file picker. Do not store the
        // expanded graph/analysis JSON in sessionStorage.
        lastLoad = {kind: 'upload', file: null};
        (async () => {
            try {
                const file = await takePendingImport();
                if (!(file instanceof Blob)) {
                    throw new Error('Файл импорта не найден. Вернитесь на главную и выберите его снова.');
                }
                await execute('upload', file);
            } catch (error) {
                showLoadError(error.message || 'Не удалось передать файл для анализа.');
            }
        })();
    } else if (app.dataset.template) {
        lastLoad = {kind: 'scenario'};
        execute('scenario');
    } else {
        lastLoad = {kind: 'upload', file: null};
        showLoadError('');
        $('status-title').textContent = 'Выберите граф для анализа';
        $('status-description').textContent = 'Загрузите файл или откройте шаблон на главной странице.';
        $('loading-message').textContent = 'Выберите исходный граф';
    }
})();
