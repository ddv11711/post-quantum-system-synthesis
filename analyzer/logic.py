"""Conservative strong-Kleene logic over finite, explicitly scoped relations."""
from enum import Enum
from collections import deque


class Truth(str, Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


TRUE, FALSE, UNKNOWN = Truth.TRUE, Truth.FALSE, Truth.UNKNOWN


def truth(value):
    if value is True:
        return TRUE
    if value is False:
        return FALSE
    if value is None:
        return UNKNOWN
    return Truth(value)


def negate(value):
    return {TRUE: FALSE, FALSE: TRUE, UNKNOWN: UNKNOWN}[truth(value)]


def conjunction(values):
    values = [truth(v) for v in values]
    return FALSE if FALSE in values else UNKNOWN if UNKNOWN in values else TRUE


def disjunction(values):
    values = [truth(v) for v in values]
    return TRUE if TRUE in values else UNKNOWN if UNKNOWN in values else FALSE


def exists(values, complete=False):
    """A missing witness can only disprove existence in a complete domain."""
    value = disjunction(values)
    return UNKNOWN if value == FALSE and not complete else value


def forall(values, complete=False):
    value = conjunction(values)
    return UNKNOWN if value == TRUE and not complete else value


def witness_path(adjacency, source, target):
    """Breadth-first positive closure; stores one shortest proof, never all paths."""
    if source == target:
        return [source]
    previous = {source: None}
    queue = deque([source])
    while queue:
        current = queue.popleft()
        for neighbor in sorted(adjacency.get(current, ())):
            if neighbor in previous:
                continue
            previous[neighbor] = current
            if neighbor == target:
                path = [target]
                while previous[path[-1]] is not None:
                    path.append(previous[path[-1]])
                return list(reversed(path))
            queue.append(neighbor)
    return None
