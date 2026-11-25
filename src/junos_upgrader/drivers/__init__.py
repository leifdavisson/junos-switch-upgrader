# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pluggable vendor driver registry for the reusable upgrade FSM."""

from junos_upgrader.drivers.base import SwitchDriver
from junos_upgrader.drivers.junos import JunosSwitchDriver

_JUNOS_DRIVER = JunosSwitchDriver()
_DRIVERS: dict[str, SwitchDriver] = {
    "juniper": _JUNOS_DRIVER,
    "junos": _JUNOS_DRIVER,
}


def get_driver(vendor: str) -> SwitchDriver:
    """Return the SwitchDriver implementation for the requested vendor."""
    key = vendor.strip().lower()
    driver = _DRIVERS.get(key)
    if driver is None:
        raise ValueError(f"Unsupported switch vendor driver: {vendor!r}")
    return driver


__all__ = ["JunosSwitchDriver", "SwitchDriver", "get_driver"]
