document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("model-file");
    const target = document.getElementById("upload-target");
    const hint = document.getElementById("file-hint");
    const description = document.getElementById("upload-description");

    const form = document.getElementById("upload-form");
    function selectedFile() { return input?.files?.[0] || null; }
    function displayFile(file) {
        if (!hint || !description) return;
        if (!file) {
            hint.textContent = "Добавить файл";
            description.textContent = "Перетащите файл или нажмите для выбора";
            hint.title = "";
            return;
        }
        hint.textContent = file.name;
        hint.title = file.name;
        const size = file.size >= 1024 * 1024
            ? `${(file.size / (1024 * 1024)).toFixed(2)} МБ`
            : `${Math.max(1, Math.round(file.size / 1024))} КБ`;
        description.textContent = `${size} · Файл выбран`;
    }

    if (input && target && hint && description) {
        input.addEventListener("change", () => { showUploadError(""); displayFile(selectedFile()); });
        ["dragenter", "dragover"].forEach(type => target.addEventListener(type, event => {
            event.preventDefault();
            target.classList.add("is-dragging");
        }));
        target.addEventListener("dragleave", event => {
            if (!target.contains(event.relatedTarget)) target.classList.remove("is-dragging");
        });
        target.addEventListener("drop", event => {
            event.preventDefault();
            target.classList.remove("is-dragging");
            const files = event.dataTransfer?.files;
            if (!files?.length) return;
            if (files.length !== 1) {
                showUploadError("Загрузите один граф за раз.");
                return;
            }
            try {
                const transfer = new DataTransfer();
                transfer.items.add(files[0]);
                input.files = transfer.files;
            } catch (error) {
                showUploadError("Не удалось прикрепить файл перетаскиванием. Нажмите на область импорта и выберите его.");
                return;
            }
            showUploadError("");
            displayFile(selectedFile());
        });
    }

    // Three-screen navigation. Existing upload drag-and-drop stays unchanged.
    const screens = {
        home: document.getElementById("home-screen"),
        normative: document.getElementById("normative-screen"),
        templates: document.getElementById("templates-screen"),
    };
    const getCurrentScreen = () => {
        const name = location.hash.slice(1);
        return Object.prototype.hasOwnProperty.call(screens, name) ? name : "home";
    };
    function switchScreen(name, animate = true) {
        for (const [key, screen] of Object.entries(screens)) {
            if (!screen) continue;
            if (!animate) screen.style.transition = "none";
            const active = key === name;
            screen.classList.toggle("is-active", active);
            screen.setAttribute("aria-hidden", String(!active));
            screen.inert = !active;
        }
        window.scrollTo({top: 0, behavior: "instant"});
        if (!animate) requestAnimationFrame(() => requestAnimationFrame(() => {
            Object.values(screens).forEach(screen => {
                if (screen) screen.style.transition = "";
            });
        }));
    }
    function openScreen(name) {
        if (getCurrentScreen() !== name) {
            history.pushState(null, "", name === "home" ?
                location.pathname + location.search : "#" + name);
        }
        switchScreen(name);
    }
    document.getElementById("open-normative")?.addEventListener("click", () => openScreen("normative"));
    document.getElementById("close-normative")?.addEventListener("click", () => openScreen("home"));
    document.getElementById("open-templates")?.addEventListener("click", () => openScreen("templates"));
    const uploadButton = document.getElementById("choose-template");
    const uploadFeedback = document.getElementById("import-feedback");
    function showUploadError(message) {
        if (uploadFeedback) {
            uploadFeedback.textContent = message;
            uploadFeedback.hidden = !message;
        }
    }
    // Keep the native multipart navigation: the selected file travels with the
    // page request and also works when browser storage or JavaScript is disabled.
    let submitting = false;
    if (form) form.noValidate = true;
    form?.addEventListener("submit", event => {
        if (submitting) { event.preventDefault(); return; }
        const file = selectedFile();
        if (!file) {
            event.preventDefault();
            showUploadError("");
            openScreen("templates");
            return;
        }
        const error = input.files.length !== 1 ? "Загрузите один граф за раз."
            : !/\.(xlsx|html|htm|json)$/i.test(file.name) ? "Поддерживаются файлы XLSX, HTML и JSON. ZIP-архивы пока не поддерживаются."
            : file.size > 32 * 1024 * 1024 ? "Размер файла не должен превышать 32 МБ." : "";
        if (error) { event.preventDefault(); showUploadError(error); return; }
        showUploadError("");
        submitting = true;
        if (uploadButton) { uploadButton.disabled = true; uploadButton.textContent = "Открываем анализ…"; }
    });
    window.addEventListener("pageshow", () => {
        submitting = false;
        if (uploadButton) { uploadButton.disabled = false; uploadButton.textContent = "Запустить анализ"; }
    });
    document.getElementById("close-templates")?.addEventListener("click", () => openScreen("home"));
    window.addEventListener("popstate", () => switchScreen(getCurrentScreen()));
    window.addEventListener("hashchange", () => switchScreen(getCurrentScreen()));
    switchScreen(getCurrentScreen(), false);

    const radios = [...document.querySelectorAll('input[name="selected-template"]')];
    const runButton = document.getElementById("run-template");
    const helper = document.getElementById("template-help");
    const updateSelection = () => {
        const selected = radios.find(radio => radio.checked && !radio.disabled);
        if (runButton) runButton.disabled = !selected;
        if (helper) helper.textContent = selected ?
            "Выбран шаблон «" + selected.value + "». Можно запускать анализ." :
            "Выберите шаблон, чтобы продолжить.";
    };
    radios.forEach(radio => radio.addEventListener("change", updateSelection));
    updateSelection();
    runButton?.addEventListener("click", () => {
        const selected = radios.find(radio => radio.checked && !radio.disabled);
        if (!selected) return;
        const url = new URL(runButton.dataset.analysisUrl, window.location.href);
        url.searchParams.set("template", selected.value);
        window.location.href = url.href;
    });
});
