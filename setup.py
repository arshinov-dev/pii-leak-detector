from pathlib import Path

from setuptools import setup


ROOT = Path(__file__).parent


def load_requirements(path: str) -> list[str]:
    requirements = []
    for line in (ROOT / path).read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        requirements.append(item)
    return requirements


DEPENDENCIES = load_requirements("requirements.txt")
DEV_DEPENDENCIES = load_requirements("requirements-dev.txt")

PY_MODULES = [
    "main",
    "settings",
    "file_search",
    "extraction_planner",
    "extraction_runner",
    "text_blocks",
    "text_extractors",
    "ocr_extractor",
    "pii_detector",
    "pii_ner",
    "risk_classifier",
]


setup(
    name="pii-leak-detector",
    version="0.1.0",
    description="CLI pipeline for detecting high-risk personal data leaks in mixed file shares.",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    packages=["pii_leak_detector"],
    py_modules=PY_MODULES,
    install_requires=DEPENDENCIES,
    extras_require={"dev": DEV_DEPENDENCIES},
    data_files=[("pii_leak_detector", ["detector_settings.json"])],
    entry_points={
        "console_scripts": [
            "pii-leak-detector=pii_leak_detector.cli:main",
            "pld=pii_leak_detector.cli:main",
        ]
    },
)
