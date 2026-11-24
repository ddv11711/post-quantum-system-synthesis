"""Discover template folders and read their PC/entity summaries."""
from pathlib import Path
import re
from zipfile import BadZipFile
from django.conf import settings
from openpyxl import load_workbook
from analyzer.excel_columns import resolve_columns
from analyzer.workbook import read_bounded_rows

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
            wb = load_workbook(files[".xlsx"], read_only=True, data_only=False)
            try:
                if len(wb.sheetnames) != 1:
                    raise ValueError('A structural template must have one worksheet')
                sheet = wb.active
                rows = read_bounded_rows(sheet, max_rows=10001, max_columns=5)
                headers = [cell.value for cell in rows[0]] if rows else []
                pc_col, _, entity_col, _, _ = resolve_columns(headers)
                pcs, entities = [], []
                for row in rows[1:]:
                    cells = [cell.value for cell in row]
                    pc = cells[pc_col] if pc_col < len(cells) else None
                    entity = cells[entity_col] if entity_col < len(cells) else None
                    scope = ' '.join(str(pc or '').split())
                    # Named shared clusters are not additional computers.
                    if re.fullmatch(r'ПК [1-9]\d*', scope) and scope not in pcs:
                        pcs.append(scope)
                    if entity is not None and str(entity).strip():
                        entities.append(str(entity).strip())
            finally:
                wb.close()
            templates.append({
                "name": folder.name, "pc_count": len(pcs), "pcs": pcs,
                "entity_count": len(entities),
                "unique_entities": list(dict.fromkeys(entities)), "valid": True,
            })
        except (OSError, ValueError, KeyError, StopIteration, BadZipFile):
            templates.append({"name": folder.name, "pc_count": 0, "pcs": [],
                              "entity_count": 0, "unique_entities": [], "valid": False})
    return templates


def find_matching_template_for_workbook(upload):
    """Find an existing *identical-in-data* template workbook (no fuzzy match).

    Only the first-column header alias (ПК/Кластер) and column order can differ.
    All five columns, all rows and their original values must otherwise match.
    In particular a changed ACL, component or connection will never silently
    inherit a template's educational security assumptions.
    """
    from openpyxl.utils.exceptions import InvalidFileException
    from zipfile import ZipFile

    # Apply the same XLSX archive limit as the regular importer before parsing.
    try:
        upload.seek(0)
        with ZipFile(upload) as archive:
            members = archive.infolist()
            if len(members) > 2048 or sum(m.file_size for m in members) > 32 * 1024 * 1024:
                return None
    except (OSError, BadZipFile, ValueError):
        return None
    finally:
        upload.seek(0)

    def canonical_rows(source):
        workbook = load_workbook(source, read_only=True, data_only=False)
        try:
            if len(workbook.sheetnames) != 1:
                return None
            rows = read_bounded_rows(workbook.active, max_rows=10001, max_columns=5)
            if not rows:
                return None
            order = resolve_columns([cell.value for cell in rows[0]])
            return tuple(
                tuple(row[index].value if index < len(row) else None for index in order)
                for row in rows[1:]
            )
        finally:
            workbook.close()

    try:
        upload.seek(0)
        source_rows = canonical_rows(upload)
    except (OSError, ValueError, KeyError, TypeError, BadZipFile, InvalidFileException):
        return None
    finally:
        upload.seek(0)

    if source_rows is None:
        return None
    if not TEMPLATE_ROOT.is_dir():
        return None
    for folder in sorted(TEMPLATE_ROOT.iterdir(), key=lambda p: p.name.casefold()):
        files = template_files(folder)
        if files is None:
            continue
        try:
            if source_rows == canonical_rows(files['.xlsx']):
                return folder
        except (OSError, ValueError, KeyError, TypeError, BadZipFile, InvalidFileException):
            continue
    return None
