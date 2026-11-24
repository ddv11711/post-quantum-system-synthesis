"""Template opt-in analysis settings; no behavior depends on a folder's name.

An ordinary five-column workbook has no authority to invent ACLs or policy.
Only an installed template with a declared scenario may enable that scenario.
"""
import json
from pathlib import Path

CONFIG_FILE = 'analysis_profile.json'


def template_analysis_config(folder):
    path = Path(folder) / CONFIG_FILE
    if not path.is_file():
        return {'mode': 'structural'}
    content = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(content, dict) or set(content) != {'version', 'mode', 'scenario', 'closed_inventory'}:
        raise ValueError('Некорректная конфигурация шаблона анализа.')
    if content['version'] != 1 or content['mode'] != 'declared_scenario' or not isinstance(content['scenario'], str) or not isinstance(content['closed_inventory'], bool):
        raise ValueError('Некорректный профиль сценария в шаблоне.')
    return content
