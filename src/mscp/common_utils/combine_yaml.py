# mscp/common_utils/combine_yaml.py

from collections.abc import MutableMapping


def deep_merge(base: MutableMapping, override: MutableMapping) -> MutableMapping:
    for key, value in override.items():
        if (
            key in base
            and isinstance(base[key], MutableMapping)
            and isinstance(value, MutableMapping)
        ):
            deep_merge(base[key], value)
        else:
            base[key] = value

    return base
