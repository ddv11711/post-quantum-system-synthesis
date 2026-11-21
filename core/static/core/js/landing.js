document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("model-file");
    const target = document.getElementById("upload-target");
    const hint = document.getElementById("file-hint");
    const description = document.getElementById("upload-description");

    let droppedFile = null;
    function selectedFile() { return droppedFile || input?.files?.[0] || null; }
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
        input.addEventListener("change", () => { droppedFile = null; displayFile(selectedFile()); });
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
            droppedFile = files[0];
            try {
                const transfer = new DataTransfer();
                transfer.items.add(files[0]);
                input.files = transfer.files;
            } catch (error) {
                // Still show the dropped file when the browser forbids setting input.files.
            }
            displayFile(files[0]);
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
    // Store only the ORIGINAL File between pages, not the expanded graph report.
    // IndexedDB supports structured-cloned File objects and avoids the small
    // per-origin sessionStorage quota.
    function savePendingImport(file) {
        return new Promise((resolve, reject) => {
            if (!window.indexedDB) {
                reject(new Error("Хранилище IndexedDB недоступно в этом браузере."));
                return;
            }
            const request = indexedDB.open("bigvizov-import-files", 1);
            request.onupgradeneeded = () => {
                const db = request.result;
                if (!db.objectStoreNames.contains("uploads")) db.createObjectStore("uploads");
            };
            request.onerror = () => reject(request.error || new Error("Не удалось открыть IndexedDB."));
            request.onblocked = () => reject(new Error("Хранилище занято другой вкладкой."));
            request.onsuccess = () => {
                const db = request.result;
                let transaction;
                try {
                    transaction = db.transaction("uploads", "readwrite");
                    transaction.objectStore("uploads").put(file, "pending");
                } catch (error) {
                    db.close();
                    reject(error);
                    return;
                }
                transaction.oncomplete = () => { db.close(); resolve(); };
                transaction.onerror = () => { db.close(); reject(transaction.error || new Error("Ошибка сохранения файла.")); };
                transaction.onabort = () => { db.close(); reject(transaction.error || new Error("Сохранение файла прервано.")); };
            };
        });
    }

    uploadButton?.addEventListener("click", async () => {
        const file = selectedFile();
        if (!file) {
            showUploadError("Сначала добавьте файл в область «Импорт», затем запустите анализ.");
            input?.focus();
            return;
        }
        if (!/\.(xlsx|html|htm|json)$/i.test(file.name)) {
            showUploadError("Поддерживаются файлы XLSX, HTML и JSON. ZIP-архивы пока не поддерживаются.");
            return;
        }
        if (file.size > 32 * 1024 * 1024) {
            showUploadError("Размер файла не должен превышать 32 МБ.");
            return;
        }
        if (uploadButton.disabled) return;
        uploadButton.disabled = true;
        uploadButton.textContent = "Открываем анализ…";
        showUploadError("");
        try {
            await savePendingImport(file);
            // Clean up legacy data from older versions if storage is available.
            try { sessionStorage.removeItem("bigvizov-upload-report"); } catch (_) {}
            const url = new URL(uploadButton.dataset.analysisUrl, location.href);
            url.searchParams.set("source", "upload");
            location.assign(url.href);
        } catch (error) {
            showUploadError("Не удалось передать файл анализатору: " + (error.message || "хранилище браузера недоступно."));
        } finally {
            uploadButton.disabled = false;
            uploadButton.textContent = "Запустить анализ";
        }
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

/* AUTO_FIX_V2_MULTIPART_FORM */
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('upload-form');
    const file = document.getElementById('model-file');
    const launch = document.getElementById('choose-template');
    if (!form || !file || !launch) return;

    // When no file is attached, preserve the existing template selection UX.
    // With an attached file, submit the real multipart form to /analysis/.
    form.noValidate = true;
    launch.addEventListener('click', (event) => {
        if (file.files && file.files.length === 1) {
            event.stopImmediatePropagation();
            return;  // normal submit-button action proceeds
        }
        event.preventDefault();
        event.stopImmediatePropagation();
        document.getElementById('open-templates')?.click();
    }, true);
    form.addEventListener('submit', (event) => {
        if (!file.files || file.files.length !== 1) {
            event.preventDefault();
            document.getElementById('open-templates')?.click();
        }
    }, true);
});
