"""Reference models for macOS security rules.

Defines the per-framework reference submodels (NIST, DISA, CIS, BSI, BZK,
HHS, custom) and the top-level ``References`` container that groups them.
"""

from typing import Any, Iterable

from pydantic import ConfigDict

from ._base import BaseModelWithAccessors

_SENTINEL = object()


class NistReferences(BaseModelWithAccessors):
    """NIST reference identifiers for a rule.

    Each list is sorted in ascending order on construction to keep the
    serialized output stable.

    Attributes:
        cce: CCE (Common Configuration Enumeration) identifiers,
            e.g. ``["CCE-94195-5"]``.
        nist_800_53r5: NIST SP 800-53 Rev. 5 control identifiers. Stored
            under the Python-friendly attribute name; serialized to YAML
            as ``800-53r5``.
        nist_800_171r3: NIST SP 800-171 Rev. 3 control identifiers.
            Serialized to YAML as ``800-171r3``.
    """

    cce: list[str] | None = None
    nist_800_53r5: list[str] | None = None
    nist_800_171r3: list[str] | None = None

    def __init__(self, **data: Any) -> None:
        """Construct from kwargs and sort all reference lists."""
        super().__init__(**data)
        if self.cce:
            self.cce = sorted(self.cce)
        if self.nist_800_53r5:
            self.nist_800_53r5 = sorted(self.nist_800_53r5)
        if self.nist_800_171r3:
            self.nist_800_171r3 = sorted(self.nist_800_171r3)


class DisaReferences(BaseModelWithAccessors):
    """DISA reference identifiers for a rule.

    Each list is sorted in ascending order on construction.

    Attributes:
        cci: CCI (Control Correlation Identifier) identifiers.
        srg: Security Requirements Guide identifiers.
        disa_stig: DISA STIG rule identifiers.
        cmmc: CMMC practice identifiers.
        sfr: Security Functional Requirement identifiers.
    """

    cci: list[str] | None = None
    srg: list[str] | None = None
    disa_stig: list[str] | None = None
    cmmc: list[str] | None = None
    sfr: list[str] | None = None

    def __init__(self, **data: Any) -> None:
        """Construct from kwargs and sort all reference lists."""
        super().__init__(**data)
        if self.cci:
            self.cci = sorted(self.cci)
        if self.srg:
            self.srg = sorted(self.srg)
        if self.sfr:
            self.sfr = sorted(self.sfr)
        if self.disa_stig:
            self.disa_stig = sorted(self.disa_stig)
        if self.cmmc:
            self.cmmc = sorted(self.cmmc)


class CisReferences(BaseModelWithAccessors):
    """CIS reference identifiers for a rule.

    Each list is sorted in ascending order on construction.

    Attributes:
        benchmark: CIS Benchmark recommendation identifiers
            (e.g. ``["1.2.3"]``).
        controls_v8: CIS Controls v8 mappings.
    """

    benchmark: list[str] | None = None
    controls_v8: list[float] | None = None

    def __init__(self, **data: Any) -> None:
        """Construct from kwargs and sort all reference lists."""
        super().__init__(**data)
        if self.benchmark:
            self.benchmark = sorted(self.benchmark)
        if self.controls_v8:
            self.controls_v8 = sorted(self.controls_v8)


class bsiReferences(BaseModelWithAccessors):
    """BSI (Bundesamt für Sicherheit in der Informationstechnik) references.

    Attributes:
        indigo: BSI Indigo profile identifiers, sorted in ascending order
            on construction.
    """

    indigo: list[str] | None = None

    def __init__(self, **data: Any) -> None:
        """Construct from kwargs and sort the reference list."""
        super().__init__(**data)
        if self.indigo:
            self.indigo = sorted(self.indigo)


class bzkReferences(BaseModelWithAccessors):
    """BZK (Ministerie van Binnenlandse Zaken en Koninkrijksrelaties) references.

    Attributes:
        bio: BIO identifiers, sorted in ascending order on construction.
    """

    bio: list[str] | None = None

    def __init__(self, **data: Any) -> None:
        """Construct from kwargs, coerce items to str, and sort the reference list.

        BIO identifiers such as ``8.27`` are parsed as floats by the YAML
        loader; they are coerced to strings here before Pydantic validates.
        """
        if isinstance(data.get("bio"), list):
            data["bio"] = [str(v) for v in data["bio"]]
        super().__init__(**data)
        if self.bio:
            self.bio = sorted(self.bio)


class hhsReferences(BaseModelWithAccessors):
    """HHS reference identifiers for a rule.

    Attributes:
        hicp: HICP identifiers, sorted in ascending order on construction.
    """

    hicp: list[str] | None = None

    def __init__(self, **data: Any) -> None:
        """Construct from kwargs and sort the reference list."""
        super().__init__(**data)
        if self.hicp:
            self.hicp = sorted(self.hicp)


class customReferences(BaseModelWithAccessors):
    """Open-ended custom reference container.

    Holds project- or deployment-specific reference identifiers that
    don't fit the other reference namespaces. Permits arbitrary extra
    fields (``extra="allow"``) so unknown reference types pass through
    unchanged.

    Attributes:
        references: Free-form reference entries, sorted in ascending order
            on construction.
    """

    model_config = ConfigDict(extra="allow")
    references: list[Any] | None = None

    def __init__(self, **data: Any) -> None:
        """Construct from kwargs and sort the reference list."""
        super().__init__(**data)
        if self.references:
            self.references = sorted(self.references)


class References(BaseModelWithAccessors):
    """Container for all reference namespaces attached to a rule.

    ``nist`` is required (every rule has at least a NIST mapping); the rest
    are optional. Extra fields are allowed so additional reference namespaces
    can be loaded without code changes.

    Attributes:
        nist: NIST identifiers (CCE, 800-53r5, 800-171r3).
        disa: DISA identifiers, if applicable.
        cis: CIS identifiers, if applicable.
        bsi: BSI identifiers, if applicable.
        bzk: BZK identifiers, if applicable.
        hhs: HHS (HICP) identifiers, if applicable.
        custom_refs: Project-specific custom references, if any.
    """

    model_config: ConfigDict = ConfigDict(extra="allow")

    nist: NistReferences
    disa: DisaReferences | None = None
    cis: CisReferences | None = None
    bsi: bsiReferences | None = None
    bzk: bzkReferences | None = None
    hhs: hhsReferences | None = None
    custom_refs: customReferences | None = None

    def get_ref(
        self,
        key: str,
        *,
        default: Any = _SENTINEL,
        case_insensitive: bool = True,
        search_order: Iterable[str] = ("nist", "disa", "cis", "bsi", "bzk"),
    ) -> Any:
        """Look up a reference value by namespace-qualified or bare key.

        Two lookup styles are supported:

        - **Namespaced**: ``"nist.cce"`` reads the named field from a
          specific submodel.
        - **Unqualified**: ``"cce"`` scans submodels in ``search_order``
          and returns the first match (values are coerced to
          ``list[str]``).

        Three legacy keys are translated automatically:
        ``"800-53r5"`` → ``"nist_800_53r5"``,
        ``"800-171r3"`` → ``"nist_800_171r3"``,
        ``"cis"`` → ``"benchmark"``.

        Args:
            key: Field name to look up, optionally namespace-prefixed
                with ``"."``.
            default: If supplied, returned when the key is missing instead
                of raising. Pass any value (including ``None``) to opt in.
            case_insensitive: If true (the default), field names are
                compared in lowercase.
            search_order: Submodel attribute names to scan in order for
                unqualified keys.

        Returns:
            The matched reference value. For unqualified lookups the value
            is coerced to ``list[str]``.

        Raises:
            KeyError: If the key is not found and no ``default`` was given.
        """

        def _dump_fields(model) -> dict[str, Any]:
            d = model.model_dump(exclude_none=False)
            if case_insensitive:
                return {k.lower(): v for k, v in d.items()}
            return d

        if key == "800-53r5":
            key = "nist_800_53r5"
        if key == "800-171r3":
            key = "nist_800_171r3"
        if key == "cis":
            key = "benchmark"

        if "." in key:
            ns, field = key.split(".", 1)
            ns_attr = ns.strip()
            field_key = field.strip().lower() if case_insensitive else field.strip()

            submodel = getattr(self, ns_attr, None)
            if submodel is None:
                if default is not _SENTINEL:
                    return default
                raise KeyError(f"Namespace '{ns_attr}' not present")

            fields = _dump_fields(submodel)
            if field_key in fields:
                return fields[field_key]

            if default is not _SENTINEL:
                return default
            raise KeyError(f"Field '{field}' not found in '{ns_attr}'")

        field_key = key.strip().lower() if case_insensitive else key.strip()

        for ns_attr in search_order:
            submodel = getattr(self, ns_attr, None)
            if submodel is None:
                continue
            fields = _dump_fields(submodel)
            if field_key in fields:
                return [str(x) for x in (fields[field_key] or [])]

        if default is not _SENTINEL:
            return default

        raise KeyError(
            f"Field '{key}' not found in any namespace ({', '.join(search_order)})"
        )
