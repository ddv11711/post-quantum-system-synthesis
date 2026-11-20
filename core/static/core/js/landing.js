
/* ==========================================
   BIGVIZOV — LANDING PAGE
   ========================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ======================================
       1. ЗАГРУЗКА ФАЙЛОВ
       ====================================== */

    const input = document.getElementById("model-file");
    const target = document.getElementById("upload-target");
    const hint = document.getElementById("file-hint");
    const form = document.getElementById("upload-form");
    const submit = form?.querySelector('.analyze-link');

    if (input && target && hint) {

        function updateFileName() {
            const file = input.files?.[0];

            hint.textContent = file
                ? file.name
                : "Добавить файл";

            hint.title = file ? file.name : "";
        }

        // Выбор файла через проводник
        input.addEventListener("change", updateFileName);
        input.addEventListener("invalid", () => {
            hint.textContent = "Сначала выберите файл графа";
        });
        form?.addEventListener('submit', (event) => {
            if (input.files.length !== 1) {
                event.preventDefault();
                hint.textContent = "Выберите один файл графа";
                return;
            }
            if (submit) {
                submit.disabled = true;
                submit.textContent = "Загружаем граф…";
            }
            form.setAttribute('aria-busy', 'true');
        });
        window.addEventListener('pageshow', () => {
            if (submit) { submit.disabled = false; submit.textContent = 'Запустить анализ'; }
            form?.removeAttribute('aria-busy');
            updateFileName();
        });

        // Подсветка области при перетаскивании
        ["dragenter", "dragover"].forEach((type) => {

            target.addEventListener(type, (event) => {
                event.preventDefault();

                target.classList.add("is-dragging");
            });

        });

        // Удаление подсветки и обработка файла
        ["dragleave", "drop"].forEach((type) => {

            target.addEventListener(type, (event) => {
                event.preventDefault();

                target.classList.remove("is-dragging");

                if (
                    type === "drop" &&
                    event.dataTransfer?.files?.length
                ) {
                    if (event.dataTransfer.files.length !== 1) {
                        input.value = '';
                        hint.textContent = "Перетащите один файл графа";
                        return;
                    }
                    input.files = event.dataTransfer.files;
                    updateFileName();
                }
            });

        });
    }


    /* ======================================
       2. ПЕРЕКЛЮЧЕНИЕ ЭКРАНОВ
       ====================================== */

    const home = document.getElementById("home-screen");

    const normative = document.getElementById(
        "normative-screen"
    );

    const openButton = document.getElementById(
        "open-normative"
    );

    const closeButton = document.getElementById(
        "close-normative"
    );

    if (
        !home ||
        !normative ||
        !openButton ||
        !closeButton
    ) {
        return;
    }


    /* ======================================
       3. ФУНКЦИЯ ПЕРЕКЛЮЧЕНИЯ
       ====================================== */

    function switchScreen(showNormative, animate = true) {

        if (!animate) {
            home.style.transition = "none";
            normative.style.transition = "none";
        }

        home.classList.toggle(
            "is-active",
            !showNormative
        );

        normative.classList.toggle(
            "is-active",
            showNormative
        );

        home.setAttribute(
            "aria-hidden",
            String(showNormative)
        );

        normative.setAttribute(
            "aria-hidden",
            String(!showNormative)
        );

        home.inert = showNormative;
        normative.inert = !showNormative;

        window.scrollTo({
            top: 0,
            behavior: "instant"
        });

        if (!animate) {
            requestAnimationFrame(() => {

                requestAnimationFrame(() => {
                    home.style.transition = "";
                    normative.style.transition = "";
                });

            });
        }
    }


    /* ======================================
       4. ОТКРЫТИЕ НОРМАТИВНОЙ БАЗЫ
       ====================================== */

    openButton.addEventListener("click", () => {

        if (window.location.hash !== "#normative") {

            history.pushState(
                { screen: "normative" },
                "",
                "#normative"
            );

        }

        switchScreen(true);

    });


    /* ======================================
       5. ВОЗВРАТ НА ГЛАВНУЮ
       ====================================== */

    closeButton.addEventListener("click", () => {

        if (window.location.hash === "#normative") {

            history.pushState(
                { screen: "home" },
                "",
                window.location.pathname +
                window.location.search
            );

        }

        switchScreen(false);

    });


    /* ======================================
       6. КНОПКИ БРАУЗЕРА НАЗАД / ВПЕРЁД
       ====================================== */

    window.addEventListener("popstate", () => {

        const showNormative =
            window.location.hash === "#normative";

        switchScreen(showNormative);

    });


    /* ======================================
       7. ПРЯМОЕ ОТКРЫТИЕ ПО ССЫЛКЕ
       ====================================== */

    const initialScreen =
        window.location.hash === "#normative";

    switchScreen(initialScreen, false);

});
