Created totally in Python programming language using the following libraries:-
- langchain
- langchain-core
- langchain-text-splitters
- langchain-ollama
- langchain-chroma
- langgraph
- chromadb
All of the above libraries are mentioned in the requirements.txt. Just install them in the virtual environment.

For llms, we have used ollama to pull and run them. There are two models used in this chatbot, phi4-mini for general use and nomic-embed-text for vector creation.

This project consists of 4 main files. 
- ingest.py - this file is responsible for actually creating the vector storage. Always execute this file before the main file to update the data.
- graph.py - contains the main pipeline of the rag chatbot.
- tools.py - contains the code for the 4 main tools that the rag chatbot provides.
- main.py - executing this file actually starts the chatbot itself.

## Directories.
- documents - The storage of all raw logs. Add any document in this directory for the rag chatbot to recoganize it. 
- vectorestore - This is the vector storage where the logs kept in the document are processed into embeddings the llm can understand.
## Tools 
There are four tools hard coded into the chatbot.
- list_files - Lists all the files inside the document directory.
- find_files - Finds all the files of the provided extentions (for example .ndjson).
- read_file - reads the raw content of the files.
- search_documents - Gives a summary of all the instances mentioned in the documents.

### Warning
This rag chatbot runs inside the terminal and will need to be wrapped around a docker.

## Setup 
- Install ollama in your computer and pull phi4-mini and nomic-embed-text.
- Run ollama in the background
- Clone and fork the files.
- Setup a virtual environment.
- In the venv, do pip -r install requirements.txt to install all the dependencies and libraries.
- First run ingest.py to create the vectorstore directory. Make sure the log files are in the documents folder.
- Now run main.py

## Langgraph pipeline
```
     User
                           |
                           v
                      LangGraph
                        Router
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
     File Commands      Log Files          RAG
          |                |                |
          v                v                v
    Python Functions   Read Files       ChromaDB
          |                |                |
          |                v                v
          |              Ollama          Retrieved
          |                |              Documents
          |                |                |
          +----------------+----------------+
                           |
                           v
                        Answer
```