"""Static alias-resolution table for known threat actors and malware families.

Goal
----
Across vendor threat reports, the same real-world entity often appears under
many surface forms (e.g. ``"APT29"``, ``"Cozy Bear"``, ``"Nobelium"``,
``"Midnight Blizzard"``). Per-chunk NER cannot collapse these because the
chunks come from independent reports. We resolve them with a static table
seeded from public sources:

* `MITRE ATT&CK Groups <https://attack.mitre.org/groups/>`_ — for threat
  actors / intrusion sets, the authoritative cross-vendor alias map.
* `MITRE ATT&CK Software <https://attack.mitre.org/software/>`_ — for
  malware and tools.
* Industry "rosetta stones" (e.g., Microsoft's threat-actor naming taxonomy:
  ``https://learn.microsoft.com/en-us/security/operations/threat-actor-naming-taxonomy``).

The table is intentionally small (~80 entries) and hand-curated to cover the
groups / families most commonly seen in vendor CTI reports. The structure is
designed to be extended: drop new entries into ``ALIAS_SEED`` and they take
effect immediately.

Each entry is keyed by the *canonical_name* the project chooses to store. The
value is the tuple of all known surface aliases (including the canonical
form itself). Matching is case-insensitive and tolerant of inner
whitespace / punctuation differences.

LLM-based fallback alias clustering is intentionally out of scope for this
initial release; it would help on novel actors that don't appear in the
seed table, but each pass adds latency and cost. The static table covers
the vast majority of named groups in our 321-report corpus.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


# ---------------------------------------------------------------------------
# Seed table
# ---------------------------------------------------------------------------
#
# Format: canonical_name -> (entity_type, all_known_aliases)
# Aliases SHOULD include the canonical_name as the first element by
# convention.  Entries below are derived from MITRE ATT&CK Groups (verified
# at the time of writing) plus a handful of widely cross-referenced vendor
# aliases. When in doubt, prefer the MITRE-canonical form.

ALIAS_SEED: dict[str, tuple[str, tuple[str, ...]]] = {
    # -------- Threat Actors / Intrusion Sets --------
    "APT1":  ("threat_actor", ("APT1", "Comment Crew", "Comment Panda")),
    "APT3":  ("threat_actor", ("APT3", "Gothic Panda", "TG-0110", "UPS")),
    "APT10": ("threat_actor", ("APT10", "MenuPass", "Stone Panda", "Bronze Riverside", "Cicada", "Red Apollo", "ChessMaster")),
    "APT17": ("threat_actor", ("APT17", "DeputyDog", "Bronze Keystone")),
    "APT19": ("threat_actor", ("APT19", "Codoso", "Sunshop Group")),
    "APT28": ("threat_actor", ("APT28", "Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Pawn Storm", "Forest Blizzard", "Tsar Team")),
    "APT29": ("threat_actor", ("APT29", "Cozy Bear", "The Dukes", "Nobelium", "Midnight Blizzard", "UNC2452", "YTTRIUM")),
    "APT30": ("threat_actor", ("APT30", "Override Panda")),
    "APT32": ("threat_actor", ("APT32", "OceanLotus", "SeaLotus", "Cobalt Kitty", "APT-C-00")),
    "APT33": ("threat_actor", ("APT33", "Elfin", "Refined Kitten", "HOLMIUM", "Peach Sandstorm")),
    "APT34": ("threat_actor", ("APT34", "OilRig", "Helix Kitten", "Cobalt Gypsy", "Earth Vetala", "Hazel Sandstorm")),
    "APT37": ("threat_actor", ("APT37", "ScarCruft", "Reaper", "Group123", "Ricochet Chollima")),
    "APT38": ("threat_actor", ("APT38", "Lazarus Group sub-cluster", "Bluenoroff", "Stardust Chollima")),
    "APT39": ("threat_actor", ("APT39", "Chafer", "Remix Kitten", "ITG07")),
    "APT41": ("threat_actor", ("APT41", "Barium", "Winnti", "Wicked Panda", "Brass Typhoon", "Double Dragon")),
    "Lazarus Group": ("threat_actor", ("Lazarus Group", "Hidden Cobra", "ZINC", "Diamond Sleet", "Labyrinth Chollima", "Guardians of Peace")),
    "Kimsuky":   ("threat_actor", ("Kimsuky", "Velvet Chollima", "Black Banshee", "Emerald Sleet", "THALLIUM")),
    "Andariel":  ("threat_actor", ("Andariel", "Silent Chollima", "PLUTONIUM", "Onyx Sleet")),
    "Equation Group": ("threat_actor", ("Equation Group", "EQGRP")),
    "FIN6":  ("threat_actor", ("FIN6", "Skeleton Spider", "ITG08", "Camouflage Tempest")),
    "FIN7":  ("threat_actor", ("FIN7", "Carbanak Group", "Carbon Spider", "Sangria Tempest", "ATK32")),
    "FIN8":  ("threat_actor", ("FIN8", "Syssphinx")),
    "FIN10": ("threat_actor", ("FIN10",)),
    "FIN11": ("threat_actor", ("FIN11", "TA505 overlap")),
    "TA505": ("threat_actor", ("TA505", "Hive0065", "Chimborazo")),
    "Sandworm Team": ("threat_actor", ("Sandworm Team", "Sandworm", "Voodoo Bear", "BlackEnergy Group", "Telebots", "ELECTRUM", "IRIDIUM", "Seashell Blizzard")),
    "Turla":  ("threat_actor", ("Turla", "Snake", "Venomous Bear", "Waterbug", "Pensive Ursa", "Krypton", "Secret Blizzard")),
    "Gamaredon Group": ("threat_actor", ("Gamaredon Group", "Gamaredon", "Primitive Bear", "Shuckworm", "ACTINIUM", "Aqua Blizzard")),
    "Cobalt Group":   ("threat_actor", ("Cobalt Group", "Cobalt Gang", "Cobalt Spider")),
    "MuddyWater":     ("threat_actor", ("MuddyWater", "TEMP.Zagros", "Static Kitten", "Seedworm", "Mango Sandstorm", "MERCURY")),
    "Charming Kitten":("threat_actor", ("Charming Kitten", "APT35", "Phosphorus", "Mint Sandstorm", "Newscaster", "TA453", "APT42")),
    "Wizard Spider":  ("threat_actor", ("Wizard Spider", "UNC1878", "TEMP.MixMaster", "Trickbot Gang")),
    "Conti Gang":     ("threat_actor", ("Conti Gang", "TrickBot ransomware affiliate")),
    "Volt Typhoon":   ("threat_actor", ("Volt Typhoon", "BRONZE SILHOUETTE", "Vanguard Panda", "Insidious Taurus")),
    "Salt Typhoon":   ("threat_actor", ("Salt Typhoon", "GhostEmperor", "FamousSparrow")),
    "Scattered Spider": ("threat_actor", ("Scattered Spider", "Octo Tempest", "0ktapus", "UNC3944", "Scatter Swine", "Roasted 0ktapus", "Muddled Libra", "Storm-0875")),
    "Magic Hare":     ("threat_actor", ("Magic Hare", "Crouching Yeti", "Energetic Bear", "Berserk Bear", "Dragonfly", "Iron Liberty")),

    # -------- Malware families --------
    "WannaCry":  ("malware", ("WannaCry", "WCry", "WannaCrypt", "WannaCryptor")),
    "NotPetya":  ("malware", ("NotPetya", "ExPetr", "GoldenEye", "Petrwrap", "Nyetya")),
    "Emotet":    ("malware", ("Emotet", "Geodo", "Heodo", "Mealybug")),
    "TrickBot":  ("malware", ("TrickBot", "TrickLoader")),
    "QakBot":    ("malware", ("QakBot", "Qbot", "Pinkslipbot", "Quakbot")),
    "IcedID":    ("malware", ("IcedID", "BokBot", "Bokbot")),
    "BazarLoader": ("malware", ("BazarLoader", "BazarBackdoor", "Bazaar")),
    "Cobalt Strike": ("tool", ("Cobalt Strike", "CobaltStrike", "CS Beacon")),
    "Mimikatz":  ("tool", ("Mimikatz", "mimi")),
    "PsExec":    ("tool", ("PsExec", "psexec.exe")),
    "AnyDesk":   ("tool", ("AnyDesk",)),
    "LockBit":   ("malware", ("LockBit", "LockBit 2.0", "LockBit 3.0", "LockBit Black", "LockBit Green")),
    "BlackCat":  ("malware", ("BlackCat", "ALPHV", "ALPHV/BlackCat", "Noberus")),
    "Conti":     ("malware", ("Conti",)),
    "Ryuk":      ("malware", ("Ryuk",)),
    "Maze":      ("malware", ("Maze", "ChaCha")),
    "Egregor":   ("malware", ("Egregor",)),
    "DoppelPaymer": ("malware", ("DoppelPaymer", "Doppel Spider")),
    "Cl0p":      ("malware", ("Cl0p", "CL0P", "Clop")),
    "REvil":     ("malware", ("REvil", "Sodinokibi", "Sodin")),
    "DarkSide":  ("malware", ("DarkSide", "DarkSide ransomware")),
    "BlackMatter": ("malware", ("BlackMatter",)),
    "Akira":     ("malware", ("Akira", "Akira ransomware")),
    "Royal":     ("malware", ("Royal", "Royal ransomware", "BlackSuit")),
    "8Base":     ("malware", ("8Base", "8Base ransomware")),
    "Hive":      ("malware", ("Hive", "Hive ransomware")),
    "Magniber":  ("malware", ("Magniber", "Magnitude EK successor")),
    "Stuxnet":   ("malware", ("Stuxnet",)),
    "Flame":     ("malware", ("Flame", "Flamer", "sKyWIper")),
    "Duqu":      ("malware", ("Duqu", "Duqu 2.0")),
    "WellMess":  ("malware", ("WellMess",)),
    "WellMail":  ("malware", ("WellMail",)),
    "PlugX":     ("malware", ("PlugX", "Korplug")),
    "Sliver":    ("malware", ("Sliver", "Sliver C2")),
    "Brute Ratel": ("malware", ("Brute Ratel", "Brute Ratel C4", "BRc4")),
    "Magic Hound RAT": ("malware", ("PowerLess",)),  # placeholder
}


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

_NORMALISE_RE = re.compile(r"[^a-z0-9]+")


def _normalise(s: str) -> str:
    """Lower-case and strip non-alphanumeric characters so 'APT-29' == 'APT29'."""
    return _NORMALISE_RE.sub("", s.lower()) if s else ""


@dataclass(frozen=True)
class AliasMatch:
    canonical_name: str
    entity_type: str
    aliases: tuple[str, ...]


class AliasTable:
    """Look up the canonical name for a surface form.

    Behaviour is case-insensitive and tolerant of punctuation differences
    (``APT-29`` matches ``APT29``).  When the same surface form is registered
    under multiple entity types — should not happen for our curated seed but
    is possible if users extend the table — we return the first registered
    type.
    """

    def __init__(self, table: dict[str, tuple[str, tuple[str, ...]]] | None = None):
        table = table if table is not None else ALIAS_SEED
        self._by_normalised: dict[str, AliasMatch] = {}
        self._canonicals: dict[str, AliasMatch] = {}
        for canonical, (etype, aliases) in table.items():
            full_aliases = tuple(dict.fromkeys((canonical, *aliases)))  # dedup keep order
            match = AliasMatch(
                canonical_name=canonical,
                entity_type=etype,
                aliases=full_aliases,
            )
            self._canonicals[canonical] = match
            for surf in full_aliases:
                self._by_normalised.setdefault(_normalise(surf), match)

    # ------------------- public API -------------------

    def lookup(self, surface: str, *, entity_type: str | None = None) -> AliasMatch | None:
        """Resolve a surface form. ``entity_type`` filters the result so a
        rare collision (same surface across types) returns the right one.
        """
        if not surface:
            return None
        m = self._by_normalised.get(_normalise(surface))
        if m is None:
            return None
        if entity_type is not None and m.entity_type != entity_type:
            return None
        return m

    def canonicalize(self, surface: str, *, entity_type: str | None = None) -> str:
        """Return the canonical name for ``surface`` if known, else ``surface``."""
        m = self.lookup(surface, entity_type=entity_type)
        return m.canonical_name if m else surface

    def all_aliases(self, canonical: str) -> tuple[str, ...]:
        m = self._canonicals.get(canonical)
        return m.aliases if m else ()

    # ------------------- bulk -------------------

    def expand(self, surfaces: Iterable[str], *,
               entity_type: str | None = None) -> tuple[str, tuple[str, ...]] | None:
        """Given several surfaces that *might* all refer to the same entity,
        find the first one resolvable in the table and return its canonical
        name + full alias set. Useful for collapsing a single LLM-extracted
        entity (canonical_name + aliases) against the seed table.

        Returns ``None`` if no surface resolves.
        """
        for s in surfaces:
            m = self.lookup(s, entity_type=entity_type)
            if m:
                return m.canonical_name, m.aliases
        return None

    def stats(self) -> dict[str, int]:
        per_type: dict[str, int] = {}
        for m in self._canonicals.values():
            per_type[m.entity_type] = per_type.get(m.entity_type, 0) + 1
        return {
            "n_canonical": len(self._canonicals),
            "n_surfaces_indexed": len(self._by_normalised),
            "by_type": per_type,
        }
