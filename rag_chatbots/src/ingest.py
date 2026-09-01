from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma


BASE_DIR = Path(__file__).resolve().parent.parent

DOCUMENTS_DIR = BASE_DIR / "documents"
VECTORSTORE_DIR = BASE_DIR / "vectorstore"

def load_custom_file(path: Path) -> Document:
    """
    Load one custom file and convert it into
    a LangChain Document.
    """

    # Read the file however your custom format requires
    content = path.read_text(encoding="utf-8")

    return Document(
        page_content=content,
        metadata={
            "source": str(path),
            "filename": path.name,
            "extension": path.suffix,
        },
    )


def load_folder(folder_path: str):
    """
    Load all files from a folder.
    """

    folder = Path(folder_path)

    if not folder.exists():
        raise FileNotFoundError(
            f"Folder does not exist: {folder}"
        )

    documents = []

    for path in folder.rglob("*"):

        if not path.is_file():
            continue

        try:
            document = load_custom_file(path)
            documents.append(document)

            print(f"Loaded: {path}")

        except Exception as e:
            print(f"Failed to load {path}: {e}")

    return documents


def create_vectorstore(folder_path: str):

    print("Loading files...")

    documents = load_folder(folder_path)

    if not documents:
        raise RuntimeError(
            "No files were found."
        )

    print(
        f"Loaded {len(documents)} files."
    )

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
    )

    chunks = splitter.split_documents(
        documents
    )

    print(
        f"Created {len(chunks)} chunks."
    )

    embeddings = OllamaEmbeddings(
        model="nomic-embed-text"
    )

    vectorstore = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=VECTORSTORE_DIR,
    )

    print("Vector database created.")

    return vectorstore


if __name__ == "__main__":

    create_vectorstore(
        "documents"
    )
