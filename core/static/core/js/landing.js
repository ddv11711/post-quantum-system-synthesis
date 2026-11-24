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
        input.addEventListener("change", () => { showUploadError(""); displayFile(selectedFile()); syncAnalysisButton(); });
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
            syncAnalysisButton();
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
    function syncAnalysisButton() {
        if (uploadButton && !submitting) uploadButton.disabled = !selectedFile();
    }
    function showUploadError(message) {
        if (uploadFeedback) {
            uploadFeedback.textContent = message;
            uploadFeedback.hidden = !message;
        }
    }
    // Keep native multipart submission. Additional requirements are optional,
    // sent in the SAME request and never stored by the browser or Django app.
    const requirementsModal = document.getElementById("requirements-modal");
    const requirementsInput = document.getElementById("requirements-file");
    const requirementsDropzone = document.getElementById("requirements-dropzone");
    const requirementsHint = document.getElementById("requirements-file-hint");
    const requirementsError = document.getElementById("requirements-modal-error");
    const requirementsSkip = document.getElementById("requirements-skip");
    const requirementsConfirm = document.getElementById("requirements-confirm");
    const requirementsClose = document.getElementById("requirements-close");
    let submitting = false;
    syncAnalysisButton();
    let requirementsApproved = false;
    let focusBeforeModal = null;

    function validateRequirements(files) {
        if (!files || !files.length) return "Выберите документы либо нажмите «Продолжить без документов».";
        if (files.length > 5) return "Можно приложить не более 5 документов.";
        for (const file of files) {
            if (!/\.(pdf|docx|txt)$/i.test(file.name)) return "Поддерживаются только PDF, DOCX и TXT.";
            if (file.size > 10 * 1024 * 1024) return "Размер каждого документа не должен превышать 10 МБ.";
            if (!file.size) return "Нельзя приложить пустой документ.";
        }
        return "";
    }
    function setRequirementsError(message) {
        if (!requirementsError) return;
        requirementsError.textContent = message;
        requirementsError.hidden = !message;
    }
    function updateRequirementsSelection() {
        const files = Array.from(requirementsInput?.files || []);
        if (requirementsHint) requirementsHint.textContent = files.length === 0 ? "Выбрать документы" :
            files.length === 1 ? files[0].name : `Выбрано документов: ${files.length}`;
        if (requirementsConfirm) requirementsConfirm.disabled = files.length === 0;
        setRequirementsError(files.length ? validateRequirements(files) : "");
    }
    function toggleRequirementsModal(open) {
        if (!requirementsModal) return;
        requirementsModal.hidden = !open;
        document.body.classList.toggle("requirements-modal-open", open);
        if (open) {
            if (requirementsInput) requirementsInput.disabled = false;
            focusBeforeModal = document.activeElement;
            requirementsClose?.focus();
        } else {
            focusBeforeModal?.focus?.();
        }
    }
    function proceedToAnalysis(skip) {
        if (skip && requirementsInput) {
            requirementsInput.value = "";
            requirementsInput.disabled = true;  // omit optional input entirely from this request
        }
        if (!skip) {
            if (requirementsInput) requirementsInput.disabled = false;
            const error = validateRequirements(Array.from(requirementsInput?.files || []));
            if (error) { setRequirementsError(error); return; }
        }
        setRequirementsError("");
        requirementsApproved = true;
        toggleRequirementsModal(false);
        // Native form submission carries the graph, CSRF token and optional
        // non-persistent requirement documents together.
        form?.requestSubmit(uploadButton);
    }
    requirementsInput?.addEventListener("change", updateRequirementsSelection);
    requirementsSkip?.addEventListener("click", () => proceedToAnalysis(true));
    requirementsConfirm?.addEventListener("click", () => proceedToAnalysis(false));
    requirementsClose?.addEventListener("click", () => toggleRequirementsModal(false));
    requirementsModal?.addEventListener("click", (event) => {
        if (event.target === requirementsModal) toggleRequirementsModal(false);
    });
    requirementsModal?.addEventListener("keydown", (event) => {
        if (event.key === "Escape") { event.preventDefault(); toggleRequirementsModal(false); }
        if (event.key === "Tab") {
            const available = [...requirementsModal.querySelectorAll('button:not(:disabled), input:not(:disabled)')]
                .filter(el => !el.closest('[hidden]'));
            if (!available.length) return;
            const first = available[0];
            const last = available[available.length - 1];
            if (event.shiftKey && document.activeElement === first) {
                event.preventDefault(); last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault(); first.focus();
            }
        }
    });
    if (requirementsDropzone && requirementsInput) {
        ["dragenter", "dragover"].forEach(type => requirementsDropzone.addEventListener(type, event => {
            event.preventDefault(); requirementsDropzone.classList.add("is-dragging");
        }));
        requirementsDropzone.addEventListener("dragleave", event => {
            if (!requirementsDropzone.contains(event.relatedTarget)) requirementsDropzone.classList.remove("is-dragging");
        });
        requirementsDropzone.addEventListener("drop", event => {
            event.preventDefault(); requirementsDropzone.classList.remove("is-dragging");
            const files = event.dataTransfer?.files;
            if (!files?.length) return;
            try {
                const data = new DataTransfer();
                Array.from(files).forEach(file => data.items.add(file));
                requirementsInput.files = data.files;
                updateRequirementsSelection();
            } catch (_) { setRequirementsError("Не удалось прикрепить файл. Нажмите на область для выбора."); }
        });
    }

    if (form) form.noValidate = true;
    form?.addEventListener("submit", event => {
        if (submitting) { event.preventDefault(); return; }
        const file = selectedFile();
        if (!file) {
            event.preventDefault();
            showUploadError("");
            syncAnalysisButton();
            return;
        }
        const error = input.files.length !== 1 ? "Загрузите один граф за раз."
            : !/\.(xlsx|html|htm|json)$/i.test(file.name) ? "Поддерживаются файлы XLSX, HTML и JSON. ZIP-архивы пока не поддерживаются."
            : file.size > 32 * 1024 * 1024 ? "Размер файла не должен превышать 32 МБ." : "";
        if (error) { event.preventDefault(); showUploadError(error); return; }
        if (!requirementsApproved && requirementsModal) {
            event.preventDefault();
            showUploadError("");
            toggleRequirementsModal(true);
            return;
        }
        showUploadError("");
        submitting = true;
        window.AnalysisLoading?.show("Запускаем анализ…");
        if (uploadButton) { uploadButton.disabled = true; uploadButton.textContent = "Открываем анализ…"; }
    });
    window.addEventListener("pageshow", () => {
        submitting = false;
        requirementsApproved = false;
        if (requirementsInput) requirementsInput.disabled = false;
        if (uploadButton) uploadButton.textContent = "Запустить анализ";
        syncAnalysisButton();
    });
    document.getElementById("close-templates")?.addEventListener("click", () => openScreen("home"));
    window.addEventListener("popstate", () => switchScreen(getCurrentScreen()));
    window.addEventListener("hashchange", () => switchScreen(getCurrentScreen()));
    switchScreen(getCurrentScreen(), false);

    // Independent PDF upload: never alters the graph-import form above.
    const normativeForm = document.getElementById("normative-import-form");
    const normativeInput = document.getElementById("normative-pdf-file");
    const normativeButton = document.getElementById("import-pdf-button");
    const normativeDropzone = document.getElementById("normative-dropzone");
    const normativeHint = document.getElementById("normative-drop-hint");
    const normativeFeedback = document.getElementById("normative-import-feedback");
    const importedList = document.getElementById("imported-documents-list");
    const importedCount = document.getElementById("imported-count");
    let normativeBusy = false;
    const uploadHint = "Перетащите PDF сюда или нажмите для выбора";
    const normativeCsrfToken = normativeForm?.querySelector('input[name="csrfmiddlewaretoken"]')?.value || "";

    function pdfFeedback(message, error = false) {
        if (!normativeFeedback) return;
        normativeFeedback.textContent = message;
        normativeFeedback.hidden = !message;
        normativeFeedback.classList.toggle("is-error", error);
    }
    function checkPdfFiles(files) {
        if (!files.length) return "Выберите хотя бы один PDF-файл.";
        if (files.length > 10) return "Можно загрузить не более 10 PDF за один раз.";
        for (const file of files) {
            if (!/\.pdf$/i.test(file.name)) return "Поддерживаются только документы PDF.";
            if (file.size > 20 * 1024 * 1024) return "Размер одного PDF не должен превышать 20 МБ.";
            if (file.size < 5) return "Нельзя загрузить пустой PDF-файл.";
        }
        return "";
    }
    function updateImportedCount() {
        if (importedCount) importedCount.textContent = importedList?.querySelectorAll(".imported-item-row").length || 0;
    }
    function buildImportedDocument(entry) {
        const row = document.createElement("div");
        row.className = "imported-item-row";
        row.dataset.filename = entry.filename;

        const link = document.createElement("a");
        link.className = "document-item imported-item";
        link.href = entry.url;
        link.download = entry.filename;

        const templateIcon = document.querySelector(".normative-original .pdf-icon");
        const icon = templateIcon?.cloneNode(true) || document.createElement("span");
        if (!templateIcon) { icon.className = "pdf-icon"; icon.textContent = "PDF"; }

        const title = document.createElement("span");
        title.className = "document-name";
        title.textContent = entry.title;

        const badge = document.createElement("span");
        badge.className = "imported-badge";
        badge.textContent = "импортирован";

        const removeButton = document.createElement("button");
        removeButton.type = "button";
        removeButton.className = "imported-delete-button";
        removeButton.dataset.filename = entry.filename;
        removeButton.dataset.deleteUrl = entry.deleteUrl;
        removeButton.setAttribute("aria-label", `Удалить ${entry.title}`);
        removeButton.innerHTML = `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M9 3.5h6l.8 1.5H20v2H4v-2h4.2L9 3.5Zm-1.1 4h8.2l-.7 11c-.1 1-.8 1.5-1.7 1.5H10.3c-.9 0-1.6-.5-1.7-1.5l-.7-11Zm3.1 2.8v6m4-6v6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

        link.append(icon, title, badge);
        row.append(link, removeButton);
        return row;
    }
    function appendImportedDocument(entry) {
        if (!importedList) return;
        document.getElementById("imported-empty")?.remove();
        importedList.prepend(buildImportedDocument(entry));
        updateImportedCount();
    }
    async function uploadNormativePDF() {
        if (normativeBusy || !normativeForm || !normativeInput) return;
        const files = Array.from(normativeInput.files || []);
        const error = checkPdfFiles(files);
        if (error) { pdfFeedback(error, true); return; }
        normativeBusy = true;
        if (normativeButton) { normativeButton.disabled = true; normativeButton.textContent = "Загрузка…"; }
        pdfFeedback("Сохраняем документы…");
        try {
            const response = await fetch(normativeForm.action, {
                method: "POST",
                body: new FormData(normativeForm),
                headers: {"Accept": "application/json", ...(normativeCsrfToken ? {"X-CSRFToken": normativeCsrfToken} : {})},
                credentials: "same-origin"
            });
            let result = {};
            try { result = await response.json(); } catch (_) { /* server returned non-JSON */ }
            if (!response.ok) throw new Error(result.error || "Не удалось загрузить документы.");
            (result.saved || []).forEach(appendImportedDocument);
            pdfFeedback(result.message || "Документы импортированы.");
            normativeInput.value = "";
            if (normativeHint) normativeHint.textContent = uploadHint;
        } catch (error) {
            pdfFeedback(error.message || "Не удалось загрузить документы.", true);
        } finally {
            normativeBusy = false;
            if (normativeButton) { normativeButton.disabled = false; normativeButton.textContent = "Импортировать PDF"; }
        }
    }
    normativeButton?.addEventListener("click", () => normativeInput?.click());
    normativeInput?.addEventListener("change", () => {
        if (normativeInput.files?.length) uploadNormativePDF();
    });
    normativeForm?.addEventListener("submit", event => {
        event.preventDefault();
        uploadNormativePDF();
    });
    if (normativeDropzone && normativeInput) {
        ["dragenter", "dragover"].forEach(type => normativeDropzone.addEventListener(type, event => {
            event.preventDefault();
            normativeDropzone.classList.add("is-dragging");
        }));
        normativeDropzone.addEventListener("dragleave", event => {
            if (!normativeDropzone.contains(event.relatedTarget)) normativeDropzone.classList.remove("is-dragging");
        });
        normativeDropzone.addEventListener("drop", event => {
            event.preventDefault();
            normativeDropzone.classList.remove("is-dragging");
            const files = event.dataTransfer?.files;
            if (!files?.length) return;
            try {
                const transfer = new DataTransfer();
                for (const file of files) transfer.items.add(file);
                normativeInput.files = transfer.files;
                uploadNormativePDF();
            } catch (_) {
                pdfFeedback("Не удалось прикрепить файлы перетаскиванием. Нажмите на область импорта.", true);
            }
        });
    }

    importedList?.addEventListener("click", async (event) => {
        const button = event.target.closest(".imported-delete-button");
        if (!button || normativeBusy) return;
        const row = button.closest(".imported-item-row");
        const filename = button.dataset.filename || row?.dataset.filename || "";
        if (!filename) return;
        if (!window.confirm(`Удалить документ «${filename}»?`)) return;

        normativeBusy = true;
        button.disabled = true;
        pdfFeedback("Удаляем документ…");
        try {
            const response = await fetch(button.dataset.deleteUrl, {
                method: "POST",
                headers: {"Accept": "application/json", ...(normativeCsrfToken ? {"X-CSRFToken": normativeCsrfToken} : {})},
                credentials: "same-origin",
            });
            let result = {};
            try { result = await response.json(); } catch (_) { /* ignore */ }
            if (!response.ok) throw new Error(result.error || "Не удалось удалить документ.");
            row?.remove();
            updateImportedCount();
            if (!importedList?.querySelector(".imported-item-row")) {
                const empty = document.createElement("p");
                empty.className = "imported-empty";
                empty.id = "imported-empty";
                empty.textContent = "Здесь появятся загруженные PDF-документы.";
                importedList?.append(empty);
            }
            pdfFeedback(result.message || "Документ удалён.");
        } catch (error) {
            pdfFeedback(error.message || "Не удалось удалить документ.", true);
            button.disabled = false;
        } finally {
            normativeBusy = false;
        }
    });

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
        window.AnalysisLoading?.show("Запускаем анализ…");
        window.location.href = url.href;
    });
});
