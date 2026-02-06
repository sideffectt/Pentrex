# Contributing to Pentrex

Thanks for your interest in contributing! Here's how you can help.

## Adding Quiz Questions

Edit `pentrex/tools/quiz.py` and add to the `QUESTIONS` dict:

```python
"your_domain": [
    {
        "q": "Your question here?",
        "options": ["A answer", "B answer", "C answer", "D answer"],
        "answer": 0,  # Index of correct answer (0=A, 1=B, 2=C, 3=D)
        "explanation": "Why this is the correct answer..."
    },
]
```

## Adding Tool Guides

Edit `pentrex/tools/toolguide.py` and add to the `TOOLS` dict:

```python
"toolname": {
    "name": "Tool Name",
    "category": "Category",
    "description": "What it does",
    "common_flags": {
        "-flag": "Description",
    },
    "examples": [
        {"desc": "What this does", "cmd": "actual command"},
    ],
}
```

## Adding Security Concepts

Edit `pentrex/tools/explain.py` and add to the `CONCEPTS` dict.

## Adding Scenarios

Edit `pentrex/tools/scenario.py` and add to the `SCENARIOS` dict.

## Pull Request Process

1. Fork the repo
2. Create your branch (`git checkout -b feature/new-questions`)
3. Make your changes
4. Test with `python3 -m tests.test_tools`
5. Commit (`git commit -m "Add 10 new web attack questions"`)
6. Push (`git push origin feature/new-questions`)
7. Open a Pull Request

## Code Style

- Keep it simple
- Add comments for complex logic
- Follow existing patterns

## Questions?

Open an issue or reach out!
