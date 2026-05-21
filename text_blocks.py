from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TextBlock:
    """
    Normalized text unit produced by extraction modules.

    Downstream PII detection should work with these blocks instead of opening
    source files directly. A block keeps text plus enough provenance to explain
    where the text came from: page, sheet, row chunk, DOCX part and so on.
    """

    file_path: str
    source_type: str
    block_index: int
    extraction_method: str
    text: str
    page_or_sheet: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def char_count(self) -> int:
        return len(self.text or "")

    @property
    def has_text(self) -> bool:
        return bool((self.text or "").strip())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["char_count"] = self.char_count
        data["has_text"] = self.has_text
        return data
