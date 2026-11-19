const fileInput = document.getElementById('model-file');
const importArea = document.getElementById('import-area');
const importLabel = document.getElementById('import-label');
const analyseButton = document.getElementById('analyse-button');
const feedback = document.getElementById('analyse-feedback');

// И выбор через окно, и перетаскивание файла обновляют одно поле input.
function updateFileName() {
    const file = fileInput.files?.[0];
    importLabel.textContent = file ? `Выбран файл: ${file.name}` : 'Импорт';
    feedback.hidden = true;
    feedback.textContent = '';
}

fileInput.addEventListener('change', updateFileName);

// Счётчик защищает подсветку от мигания при переходе над дочерними элементами.
let dragDepth = 0;

importArea.addEventListener('dragenter', (event) => {
    event.preventDefault();
    dragDepth += 1;
    importArea.classList.add('import-area--dragover');
});

importArea.addEventListener('dragover', (event) => {
    event.preventDefault(); // разрешаем сброс файла в область
    event.dataTransfer.dropEffect = 'copy';
});

importArea.addEventListener('dragleave', (event) => {
    event.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) {
        importArea.classList.remove('import-area--dragover');
    }
});

importArea.addEventListener('drop', (event) => {
    event.preventDefault(); // браузер не откроет файл вместо сайта
    dragDepth = 0;
    importArea.classList.remove('import-area--dragover');

    const file = event.dataTransfer?.files?.[0];
    if (!file) return;

    // Сохраняем один файл в том же input, который используется при клике.
    const transfer = new DataTransfer();
    transfer.items.add(file);
    fileInput.files = transfer.files;
    fileInput.dispatchEvent(new Event('change', { bubbles: true }));
});

analyseButton.addEventListener('click', () => {
    const file = fileInput.files?.[0];

    if (!file) {
        feedback.textContent = 'Сначала выберите файл в области «Импорт».';
    } else {
        feedback.textContent = 'Файл выбран. Анализ пока не подключён — это прототип интерфейса.';
    }

    feedback.hidden = false;
});
