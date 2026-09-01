from pathlib import Path
import json


BASE_DIR = Path(__file__).resolve().parent.parent
DOCUMENTS_DIR = (BASE_DIR / "documents").resolve()


def list_files() -> str:
    if not DOCUMENTS_DIR.exists():
        return "The documents directory does not exist."

    files = [
        path
        for path in DOCUMENTS_DIR.rglob("*")
        if path.is_file()
    ]

    if not files:
        return "The documents directory is empty."

    return "\n".join(
        str(path.relative_to(DOCUMENTS_DIR))
        for path in files
    )


def find_files(extension: str) -> str:
    if not extension.startswith("."):
        extension = "." + extension

    extension = extension.lower()

    files = [
        path
        for path in DOCUMENTS_DIR.rglob("*")
        if path.is_file()
        and path.suffix.lower() == extension
    ]

    if not files:
        return f"No {extension} files were found."

    return "\n".join(
        str(path.relative_to(DOCUMENTS_DIR))
        for path in files
    )


def read_file(filename: str) -> str:
    path = (DOCUMENTS_DIR / filename).resolve()

    if DOCUMENTS_DIR not in path.parents:
        return "Access denied."

    if not path.exists():
        return f"File '{filename}' does not exist."

    if not path.is_file():
        return f"'{filename}' is not a file."

    try:
        if path.suffix.lower() == ".json":
            with open(path, "r", encoding="utf-8") as file:
                data = json.load(file)

            return json.dumps(
                data,
                indent=2,
                ensure_ascii=False
            )

        return path.read_text(
            encoding="utf-8"
        )

    except Exception as e:
        return f"Could not read '{filename}': {e}"
