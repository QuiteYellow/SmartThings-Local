"""Appliance descriptors registry.

Adding a new appliance class:
  1. Write `mqtt_demo/samples/<class>.py` with an ApplianceDescriptor
     named after the class (uppercase, e.g. OVEN).
  2. Add it to DESCRIPTORS below.
  3. Set DEVICE_CLASS=<class> in the per-device .env.

mqtt_demo/__main__.py imports get_descriptor(name) to look up the
descriptor at startup; the bridge itself stays class-agnostic.
"""
from ..descriptor import ApplianceDescriptor
from .dryer import DRYER
from .oven import OVEN
from .fridge import FRIDGE



DESCRIPTORS: dict[str, ApplianceDescriptor] = {
    DRYER.name: DRYER,
    OVEN.name:  OVEN,
    FRIDGE.name: FRIDGE,
}


def get_descriptor(name: str) -> ApplianceDescriptor:
    try:
        return DESCRIPTORS[name]
    except KeyError:
        raise ValueError(
            f"unknown DEVICE_CLASS={name!r}; "
            f"available: {sorted(DESCRIPTORS)}") from None


__all__ = ['ApplianceDescriptor', 'DESCRIPTORS', 'get_descriptor']
