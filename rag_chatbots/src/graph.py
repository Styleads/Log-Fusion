from typing import TypedDict
from pathlib import Path

from langchain_core.messages import SystemMessage, HumanMessage
from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_chroma import Chroma
from langgraph.graph import StateGraph, START, END

from tools import list_files, find_files, read_file


BASE_DIR = Path(__file__).resolve().parent.parent
VECTORSTORE_DIR = BASE_DIR / "vectorstore"


embeddings = OllamaEmbeddings(
    model="nomic-embed-text"
)


vectorstore = Chroma(
    persist_directory=str(VECTORSTORE_DIR),
    embedding_function=embeddings,
)


retriever = vectorstore.as_retriever(
    search_kwargs={"k": 4}
)


llm = ChatOllama(
    model="phi4-mini",
    temperature=0
)


class State(TypedDict):
    question: str
    context: str
    answer: str


def router(state: State):
    question = state["question"].lower().strip()

    if (
        "tool" in question
        or question == "tools"
        or question == "list tools"
        or question == "list your tools"
        or "available tools" in question
        or "what can you do" in question
    ):
        return "tools"

    if question == "list_files":
        return "list_files"

    if question.startswith("find_files"):
        return "find_files"

    if question.startswith("read_file"):
        return "read_file"

    if question.startswith("search_documents"):
        return "search_documents"

    if (
        "list files" in question
        or "what files" in question
        or "which files" in question
    ):
        return "list_files"

    if (
        ".ndjson" in question
        or "ndjson" in question
    ):
        return "ndjson_files"

    if (
        ".json" in question
        or "json" in question
    ):
        return "json_files"

    if (
        "log" in question
        or "logs" in question
        or ".log" in question
    ):
        return "ndjson_files"

    if (
        "file" in question
        or "folder" in question
        or "directory" in question
    ):
        return "list_files"

    return "rag"


def tools_node(state: State):
    return {
        "answer": """I have the following tools:

- list_files — lists all files in the documents directory
- find_files — finds files by extension
- read_file — reads a specific file
- search_documents — searches the indexed documents"""
    }


def list_files_node(state: State):
    files = list_files()

    if files.startswith("The documents directory"):
        return {
            "answer": files
        }

    if files == "The documents directory is empty.":
        return {
            "answer": files
        }

    file_list = "\n".join(
        f"- {filename}"
        for filename in files.splitlines()
    )

    return {
        "answer": f"Files in the documents directory:\n\n{file_list}"
    }


def find_files_node(state: State):
    question = state["question"].strip()

    parts = question.split(maxsplit=1)

    if len(parts) < 2:
        return {
            "answer": "Please specify a file extension."
        }

    extension = parts[1].strip()

    files = find_files(extension)

    if files.startswith("No "):
        return {
            "answer": files
        }

    file_list = "\n".join(
        f"- {filename}"
        for filename in files.splitlines()
    )

    return {
        "answer": file_list
    }


def read_file_node(state: State):
    question = state["question"].strip()

    parts = question.split(maxsplit=1)

    if len(parts) < 2:
        return {
            "answer": "Please specify a filename."
        }

    filename = parts[1].strip()

    content = read_file(filename)

    return {
        "answer": content
    }


def search_documents_node(state: State):
    question = state["question"].strip()

    parts = question.split(maxsplit=1)

    if len(parts) < 2:
        return {
            "answer": "Please provide something to search for."
        }

    query = parts[1].strip()

    documents = retriever.invoke(query)

    if not documents:
        return {
            "answer": "No relevant documents were found."
        }

    results = []

    for document in documents:
        source = document.metadata.get(
            "source",
            "unknown"
        )

        results.append(
            f"SOURCE: {source}\n\n"
            f"{document.page_content}"
        )

    return {
        "context": "\n\n---\n\n".join(results)
    }


def read_extension_files(extension: str):
    files = find_files(extension)

    if files.startswith("No "):
        return files

    filenames = files.splitlines()

    contents = []

    for filename in filenames:
        content = read_file(filename)

        contents.append(
            f"FILE: {filename}\n\nCONTENT:\n{content}"
        )

    return "\n\n---\n\n".join(contents)


def ndjson_files_node(state: State):
    return {
        "context": read_extension_files(".ndjson")
    }


def json_files_node(state: State):
    return {
        "context": read_extension_files(".json")
    }


def rag_node(state: State):
    question = state["question"]

    documents = retriever.invoke(question)

    if not documents:
        return {
            "context": "No relevant documents were found."
        }

    context_parts = []

    for document in documents:
        source = document.metadata.get(
            "source",
            "unknown"
        )

        context_parts.append(
            f"SOURCE: {source}\n\n"
            f"{document.page_content}"
        )

    return {
        "context": "\n\n---\n\n".join(context_parts)
    }


def generate(state: State):
    question = state["question"]
    context = state["context"]

    system_prompt = f"""
You are a local RAG assistant.

Use the retrieved information to answer the user's question.

Rules:

- Do not invent information.
- Do not claim to have accessed files that are not in the context.
- Summarize information when the user asks for a summary.
- Do not dump raw JSON or NDJSON unless the user explicitly asks for it.
- Interpret JSON and NDJSON records and explain them naturally.
- Be concise unless the user asks for detail.

Retrieved information:

{context}
"""

    response = llm.invoke(
        [
            SystemMessage(content=system_prompt),
            HumanMessage(content=question)
        ]
    )

    return {
        "answer": response.content
    }


builder = StateGraph(State)

builder.add_node(
    "router",
    lambda state: state
)

builder.add_node(
    "tools",
    tools_node
)

builder.add_node(
    "list_files",
    list_files_node
)

builder.add_node(
    "find_files",
    find_files_node
)

builder.add_node(
    "read_file",
    read_file_node
)

builder.add_node(
    "search_documents",
    search_documents_node
)

builder.add_node(
    "ndjson_files",
    ndjson_files_node
)

builder.add_node(
    "json_files",
    json_files_node
)

builder.add_node(
    "rag",
    rag_node
)

builder.add_node(
    "generate",
    generate
)

builder.add_edge(
    START,
    "router"
)

builder.add_conditional_edges(
    "router",
    router,
    {
        "tools": "tools",
        "list_files": "list_files",
        "find_files": "find_files",
        "read_file": "read_file",
        "search_documents": "search_documents",
        "ndjson_files": "ndjson_files",
        "json_files": "json_files",
        "rag": "rag"
    }
)

builder.add_edge(
    "tools",
    END
)

builder.add_edge(
    "list_files",
    END
)

builder.add_edge(
    "find_files",
    END
)

builder.add_edge(
    "read_file",
    END
)

builder.add_edge(
    "search_documents",
    "generate"
)

builder.add_edge(
    "ndjson_files",
    "generate"
)

builder.add_edge(
    "json_files",
    "generate"
)

builder.add_edge(
    "rag",
    "generate"
)

builder.add_edge(
    "generate",
    END
)

graph = builder.compile()
