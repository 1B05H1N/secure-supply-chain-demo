"""Minimal application packaged by the supply-chain demo."""


def greet(name: str) -> str:
    cleaned = " ".join(name.split())
    if not cleaned:
        raise ValueError("name must not be empty")
    return f"Hello, {cleaned}."
