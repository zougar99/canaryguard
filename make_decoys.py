import sys

from canaryguard.config import Config
from canaryguard.decoys import DecoyManager


def main():
    config = Config.load()
    mgr = DecoyManager(config)
    kinds = sys.argv[1:] or None
    files = mgr.generate(kinds=kinds)
    print("\nGenerated decoys:")
    for f in files:
        print(" -", f)


if __name__ == "__main__":
    main()