/* One scenario, one graph workspace, independently verified repair. */
(() => {
    'use strict';
    const $ = id => document.getElementById(id);
    const app = $('security-app');
    if (!app) return;
    let report = null, graphView = null, phase = 'before', busy = false;
    const icon = {
        warning: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3 3 7v6c0 5 9 8 9 8s9-3 9-8V7l-9-4Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M12 8v5m0 3v.1" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        success: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3 3 7v6c0 5 9 8 9 8s9-3 9-8V7l-9-4Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="m8 12 3 3 5-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>'
    };
    const findingCopy = {
        nas_forbidden: {
            title: 'Запрещённый доступ к NAS', fixed: 'Доступ к NAS закрыт',
            description: 'Пользователь 2 на ПК 2 может читать сетевой диск вопреки политике доступа.',
            solution: 'Оба обходных пути перекрыты. Разрешённый доступ сохранён.',
        },
        pc1_filtering: {
            title: 'Нет межсетевого экрана', fixed: 'Межсетевой экран восстановлен',
            description: 'На ПК 1 отсутствует компонент, который фильтрует входящий трафик.',
            solution: 'Входящий трафик ПК 1 снова проходит через защитный фильтр.',
        },
        pc1_logging: {
            title: 'События не записываются', fixed: 'Регистрация событий включена',
            description: 'Служба регистрации на ПК 1 выключена. Сетевые события остаются без записи.',
            solution: 'Служба включена. Регистрация обязательных событий проверена.',
        },
    };
    function element(tag, value, cls) {
        const node = document.createElement(tag);
        if (value != null) node.textContent = value;
        if (cls) node.className = cls;
        return node;
    }
    function state(name = phase) { return report?.states?.[name === 'after' ? 'repaired' : name]; }
    function resultList(snapshot) { return snapshot?.analysis?.results || []; }
    function summary(snapshot) {
        const results = resultList(snapshot);
        return {total: results.length, pass: results.filter(r => r.status === 'PASS').length,
            fail: results.filter(r => r.status === 'FAIL').length,
            unknown: results.filter(r => !['PASS', 'FAIL'].includes(r.status)).length};
    }
    function verifiedClean() {
        const latest = state('repaired'), totals = summary(latest);
        return Boolean(latest && totals.total && totals.pass === totals.total && !latest.graph.summary.violators.length && !latest.analysis.model_errors?.length);
    }
    function feedback(message) { $('page-feedback').textContent = message; $('page-feedback').hidden = !message; }
    function renderStatus() {
        const clean = verifiedClean(), before = summary(state('before'));
        const failedRepair = Boolean(report?.repair && !state('repaired'));
        $('system-status').dataset.state = busy ? 'loading' : clean ? 'success' : 'warning';
        $('status-symbol').innerHTML = busy ? '<span class="spinner"></span>' : icon[clean ? 'success' : 'warning'];
        $('status-title').textContent = busy ? 'Исправляем и проверяем…' : clean ? 'Все найденные уязвимости устранены' : failedRepair ? 'Подтверждённого исправления пока нет' : `В графе найдены уязвимости: ${before.fail}`;
        $('status-description').textContent = busy ? 'Применяем изменения и повторно проверяем все требования сценария.' : clean ? 'Повторная проверка пройдена. Доступ остальных пользователей сохранён.' : failedRepair ? 'Исходный граф сохранён. Неустранённые нарушения показаны справа.' : 'Закроем запрещённый доступ и восстановим защиту компонентов.';
        $('repair-button').disabled = busy || clean || !report;
        $('repair-button').textContent = busy ? 'Исправляем…' : clean ? 'Уязвимости устранены' : failedRepair ? 'Повторить исправление' : 'Исправить уязвимости';
        $('before-tab').disabled = busy || !report;
        $('after-tab').disabled = busy || !state('repaired');
    }
    function renderFindings() {
        const current = state(), before = state('before'), totals = summary(current);
        const repairedById = new Map(resultList(state('repaired')).map(r => [r.id, r]));
        const originalFindings = (before.graph.findings || []).filter(f => f.status === 'FAIL');
        originalFindings.sort((a, b) => Number(Boolean(b.offender)) - Number(Boolean(a.offender)));
        const list = $('findings-list'); list.replaceChildren();
        $('findings-title').textContent = phase === 'after' ? 'Что исправлено' : state('repaired') ? 'До исправления' : 'Что нужно исправить';
        $('finding-count').hidden = false;
        $('finding-count').textContent = originalFindings.length;
        $('finding-count').classList.toggle('is-fixed', phase === 'after' && totals.fail === 0);
        for (const finding of originalFindings) {
            const fixed = phase === 'after' && repairedById.get(finding.id)?.status === 'PASS';
            const copy = findingCopy[finding.id];
            const card = element('button', null, `finding-card ${fixed ? 'is-fixed' : ''}`);
            card.type = 'button'; card.dataset.findingId = finding.id;
            const mark = element('span', fixed ? '✓' : '!', 'finding-mark'); mark.setAttribute('aria-hidden', 'true');
            const content = element('span', null, 'finding-content');
            content.append(element('strong', copy ? (fixed ? copy.fixed : copy.title) : finding.name), element('span', copy ? (fixed ? copy.solution : copy.description) : finding.message));
            card.append(mark, content);
            card.addEventListener('click', () => {
                const keys = finding.offender ? [finding.offender] : (finding.causes?.length ? finding.causes : [finding.object]);
                graphView?.focusNodes(keys.filter(Boolean));
                if (window.matchMedia('(max-width: 900px)').matches) $('security-graph').scrollIntoView({block: 'center', behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth'});
            });
            list.append(card);
        }
        $('check-count').textContent = `${totals.pass} из ${totals.total} проверок пройдено`;
        $('check-description').textContent = totals.unknown ? `Есть неизвестные или непроверенные условия: ${totals.unknown}.` : phase === 'after' && totals.fail === 0 ? 'Все требования сценария выполнены.' : 'Остальные требования выполняются.';
        $('check-icon').classList.toggle('is-complete', totals.total > 0 && totals.pass === totals.total);
        $('before-tab').setAttribute('aria-pressed', String(phase === 'before'));
        $('after-tab').setAttribute('aria-pressed', String(phase === 'after'));
        $('node-count').textContent = current.graph.nodes.length;
        $('edge-count').textContent = new Intl.NumberFormat('ru-RU').format(current.graph.summary.structural_edges);
    }
    function setPhase(next) {
        if (busy || (next === 'after' && !state('repaired'))) return;
        phase = graphView.setPhase(next);
        renderFindings();
    }
    function renderReport(next, repaired) {
        report = next;
        graphView?.destroy();
        phase = repaired && report.states.repaired ? 'after' : 'before';
        graphView = window.SecurityGraphComparison.mount($('security-graph'), report, {compact: true, phase, beforeState: 'before'});
        $('security-graph').setAttribute('aria-busy', 'false');
        renderFindings();
    }
    async function execute(repair) {
        if (busy) return;
        busy = true; feedback('');
        if (report) renderStatus();
        else {
            $('retry-button').hidden = true;
            $('loading-message').textContent = 'Загружаем граф системы';
            $('security-graph').setAttribute('aria-busy', 'true');
            $('system-status').dataset.state = 'loading';
            $('status-symbol').innerHTML = '<span class="spinner"></span>';
            $('status-title').textContent = 'Проверяем граф…';
            $('status-description').textContent = 'Загружаем компоненты и проверяем доступ к ресурсам.';
        }
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 45000);
        try {
            const response = await fetch(app.dataset.scenarioUrl, {
                method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value},
                body: JSON.stringify({repair}), signal: controller.signal,
            });
            let data;
            try { data = await response.json(); } catch (_) { throw new Error('Сервер вернул некорректный ответ. Повторите попытку.'); }
            if (!response.ok) throw new Error(data.error || 'Не удалось выполнить проверку. Повторите попытку.');
            if (!data.states?.before?.graph?.nodes || !Array.isArray(data.states.before.analysis?.results)) throw new Error('В ответе отсутствует проверенный граф. Повторите попытку.');
            renderReport(data, repair);
            if (repair && !data.states.repaired) feedback('Не удалось подтвердить исправление всех нарушений. Исходный граф сохранён.');
        } catch (error) {
            const message = error.name === 'AbortError' ? 'Сервер не ответил вовремя. Повторите попытку.' : error.name === 'TypeError' ? 'Не удалось связаться с сервером. Повторите попытку.' : error.message;
            feedback(message);
            if (!report) {
                $('loading-message').textContent = 'Граф не загрузился';
                $('retry-button').hidden = false;
                $('security-graph').setAttribute('aria-busy', 'false');
                $('system-status').dataset.state = 'warning';
                $('status-symbol').innerHTML = icon.warning;
                $('status-title').textContent = 'Не удалось загрузить граф';
                $('status-description').textContent = 'Повторите загрузку, чтобы начать проверку.';
                $('check-count').textContent = 'Проверка не выполнена';
                $('check-description').textContent = 'Результатов пока нет.';
            }
        } finally {
            window.clearTimeout(timeout); busy = false;
            if (report) renderStatus();
        }
    }
    $('repair-button').addEventListener('click', () => execute(true));
    $('retry-button').addEventListener('click', () => execute(false));
    $('before-tab').addEventListener('click', () => setPhase('before'));
    $('after-tab').addEventListener('click', () => setPhase('after'));
    execute(false);
})();
