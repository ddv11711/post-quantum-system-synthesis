"""Discover template folders and read their PC/entity summaries."""
from pathlib import Path
from django.conf import settings
from openpyxl import load_workbook
from analyzer.excel_columns import resolve_columns

TEMPLATE_ROOT = settings.BASE_DIR / "data" / "sources"
REQUIRED_EXTENSIONS = {".xlsx", ".html", ".docx"}

def template_files(folder):
    if not folder.is_dir() or folder.is_symlink():
        return None
    files = [f for f in folder.iterdir() if f.is_file() and not f.is_symlink()]
    found = {}
    for ext in REQUIRED_EXTENSIONS:
        matches = [f for f in files if f.suffix.lower() == ext]
        if len(matches) != 1:
            return None
        found[ext] = matches[0]
    return found

def resolve_template(name):
    if not isinstance(name, str) or name in {"", ".", ".."}:
        return None
    if Path(name).name != name or "/" in name or "\\" in name:
        return None
    folder = TEMPLATE_ROOT / name
    if not folder.is_dir() or folder.is_symlink():
        return None
    if not folder.resolve().is_relative_to(TEMPLATE_ROOT.resolve()):
        return None
    return folder if template_files(folder) else None

def list_templates():
    TEMPLATE_ROOT.mkdir(parents=True, exist_ok=True)
    templates = []
    for folder in sorted(TEMPLATE_ROOT.iterdir(), key=lambda p: p.name.casefold()):
        files = template_files(folder)
        if files is None:
            continue
        try:
            wb = load_workbook(files[".xlsx"], read_only=True, data_only=True)
            try:
                sheet = wb.active
                headers = list(next(sheet.iter_rows(min_row=1, max_row=1, values_only=True)))
                pc_col, _, entity_col, _, _ = resolve_columns(headers)
                pcs, entities = [], []
                for cells in sheet.iter_rows(min_row=2, values_only=True):
                    pc = cells[pc_col] if pc_col < len(cells) else None
                    entity = cells[entity_col] if entity_col < len(cells) else None
                    if pc is not None and str(pc).strip() and str(pc).strip() not in pcs:
                        pcs.append(str(pc).strip())
                    if entity is not None and str(entity).strip():
                        entities.append(str(entity).strip())
            finally:
                wb.close()
            templates.append({
                "name": folder.name, "pc_count": len(pcs), "pcs": pcs,
                "entity_count": len(entities),
                "unique_entities": list(dict.fromkeys(entities)), "valid": True,
            })
        except (OSError, ValueError, KeyError, StopIteration):
            templates.append({"name": folder.name, "pc_count": 0, "pcs": [],
                              "entity_count": 0, "unique_entities": [], "valid": False})
    return templates
