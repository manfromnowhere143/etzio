"""The roster, assembled. `default_roster()` returns one instance of each unit."""

from .base import (
    Aquila,
    Camillus,
    Cato,
    Fabius,
    Fabricius,
    Marcellus,
    Minerva,
    Scipio,
    Target,
    Unit,
    Velites,
)


def default_roster() -> dict[str, Unit]:
    return {
        "SCIPIO": Scipio(),
        "FABIUS": Fabius(),
        "VELITES": Velites(),
        "MARCELLUS": Marcellus(),
        "CATO": Cato(),
        "CAMILLUS": Camillus(),
        "FABRICIUS": Fabricius(),
        "AQUILA": Aquila(),
        "MINERVA": Minerva(),
    }


__all__ = [
    "Unit", "Target", "default_roster",
    "Scipio", "Fabius", "Velites", "Marcellus", "Cato",
    "Camillus", "Fabricius", "Aquila", "Minerva",
]
