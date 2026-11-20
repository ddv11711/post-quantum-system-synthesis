"""Resolve the five semantic fields of a template workbook by its headings.

Supports common alternative names and old workbooks with arbitrary headings
when their five columns retain the original A:E order.
"""
import re
import unicodedata

FIELDS = ("scope", "id", "entity", "incoming", "outgoing")
CANONICAL = ("ПК", "ID", "Сущность", "Вход", "Выход")
ALIASES = {
    "scope": {"пк", "кластер", "компьютер", "узел", "хост", "pc", "cluster", "host", "workstation"},
    "id": {"id", "ид", "идентификатор", "код", "номер", "id сущности"},
    "entity": {"сущность", "наименование сущности", "название сущности", "компонент", "объект", "entity", "name", "название"},
    "incoming": {"вход", "входящие", "входящие связи", "связи вход", "incoming", "input", "in"},
    "outgoing": {"выход", "исходящие", "исходящие связи", "связи выход", "outgoing", "output", "out"},
}

def _normalize(value):
    text = unicodedata.normalize("NFKC", str(value or "")).casefold().replace("ё", "е")
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", text)).strip()

_NORMALIZED = {key: {_normalize(a) for a in names} for key, names in ALIASES.items()}


def resolve_columns(headers):
    """Return indices in order: scope, ID, entity, incoming, outgoing.

    If a heading is unknown, its original position may be used. This is only
    allowed when all recognized headings also remain in their original positions;
    otherwise the intended meaning of an unknown heading is ambiguous.
    """
    if len(headers) != 5 or any(not _normalize(h) for h in headers):
        raise ValueError("Ожидаются пять непустых заголовков Excel: кластер/ПК, ID, сущность, вход, выход")
    found = {}
    for index, value in enumerate(headers):
        normalized = _normalize(value)
        matches = [key for key, names in _NORMALIZED.items() if normalized in names]
        if len(matches) > 1:
            raise ValueError(f"Неоднозначный заголовок: {value!r}")
        if matches:
            key = matches[0]
            if key in found:
                raise ValueError(f"Повторяющийся столбец {key!r}")
            found[key] = index
    if len(found) < 5:
        # Avoid guessing roles when the user has changed column positions.
        if any(found[key] != position for position, key in enumerate(FIELDS) if key in found):
            raise ValueError("Неизвестные заголовки при изменённом порядке столбцов: уточните названия")
        return tuple(range(5))
    return tuple(found[key] for key in FIELDS)
