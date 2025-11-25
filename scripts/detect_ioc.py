import json
from pathlib import Path
from hashlib import sha1
from typing import Callable, Dict

ROOT_DIR = Path(__file__).parent.parent.resolve()
LISTS_DIR = ROOT_DIR.joinpath("lists")
SUS_FILES = LISTS_DIR.joinpath("susfiles.txt").read_text().splitlines()
HASHES = {
    h: n
    for n, h in [
        line.strip().split(",")
        for line in LISTS_DIR.joinpath("hashes.txt").read_text().splitlines()
    ]
}


Check = Callable[[Path, str], bool]


class Detection:
    def __init__(self, check: Check, reason: str):
        self.reason = reason
        self._check = check

    def __call__(self, path: Path, file: str) -> Dict | None:
        if self._check(path, file):
            filepath = Path(path).joinpath(file)
            return {
                "file": str(filepath),
                "hash": sha1(filepath.read_bytes()).hexdigest(),
                "reason": self.reason,
            }


file_check = Detection(
    lambda _, file: file in SUS_FILES, "matches known suspicious filename"
)
package_json_check = Detection(
    lambda path, file: file == "package.json"
    and "setup_bun.js" in Path(path).joinpath(file).read_text(),
    "contains bun preinstall script",
)
gh_action_check = Detection(
    lambda path, file: file == "discussion.yaml" and ".github/workflows" in str(path),
    "GitHub discussion workflow detected",
)
bun_binary_check = Detection(
    lambda path, file: path == Path.home().joinpath(".bun/bin") and file == "bun",
    "bun binary exists in home directory",
)
hash_checks = Detection(
    lambda path, file: file in HASHES.values()
    and HASHES[sha1(Path(path).joinpath(file).read_bytes()).hexdigest()] == file,
    "matches known suspicious file hash",
)


def detect_file_ioc(start_dir: Path):
    detections = [
        file_check,
        package_json_check,
        gh_action_check,
        bun_binary_check,
        hash_checks,
    ]
    for path, dirs, files in start_dir.walk():
        for f in files:
            for detection in detections:
                try:
                    result = detection(Path(path), f)
                    if result:
                        yield result
                except Exception:
                    pass


def main():
    for file_info in detect_file_ioc(Path.home()):
        print(json.dumps(file_info))


if __name__ == "__main__":
    main()
