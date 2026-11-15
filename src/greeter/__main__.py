import sys

from greeter import greet


def main() -> None:
    print(greet(" ".join(sys.argv[1:]) or "world"))


if __name__ == "__main__":
    main()
