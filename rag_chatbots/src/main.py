from graph import graph


def main():
    print("RAG Chatbot")
    print("Type 'exit' to quit.\n")

    while True:
        question = input("You: ").strip()

        if question.lower() in {
            "exit",
            "quit"
        }:
            break

        result = graph.invoke(
            {
                "question": question,
                "context": "",
                "answer": ""
            }
        )

        print("\nAssistant:")
        print(result["answer"])
        print()


if __name__ == "__main__":
    main()
