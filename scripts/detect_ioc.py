import json
from pathlib import Path
from hashlib import sha1
import sys
from typing import Callable, Dict


SUS_FILES = [
    "bun_environment.js",
    "cloud.json",
    "contents.json",
    "environment.json",
    "npm.json",
    "secrets.json",
    "setup_bun.js",
    "system.json",
    "trufflehog-findings.json",
    "truffleSecrets.json",
]

HASHES = {
    "d60ec97eea19fffb4809bc35b91033b52490ca11": "bun_environment.js",
    "3d7570d14d34b0ba137d502f042b27b0f37a59fa": "bun_environment.js",
    "d1829b4708126dcc7bea7437c04d1f10eacd4a16": "setup_bun.js",
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


filename_check = Detection(
    lambda _, file: file in SUS_FILES, "matches known suspicious filename"
)
package_json_check = Detection(
    lambda path, file: file == "package.json"
    and any(
        [
            txt in Path(path).joinpath(file).read_text()
            for txt in ["setup_bun.js", "bun_environment.js"]
        ]
    ),
    "contains bun preinstall script",
)
bun_binary_check = Detection(
    lambda path, file: file == "bun" and path.parts[-2:] == (".bun", "bin"),
    "bun binary exists in home directory",
)
hash_checks = Detection(
    lambda path, file: file in HASHES.values()
    and HASHES[sha1(Path(path).joinpath(file).read_bytes()).hexdigest()] == file,
    "matches known suspicious file hash",
)
git_log_check = Detection(
    lambda path, file: file == "HEAD"
    and path.parts[-2:] == (".git", "logs")
    and any(
        [
            txt in Path(path).joinpath(file).read_text().lower()
            for txt in ["hulud", "Add Discussion"]
        ]
    ),
    "Git log indicates Shai Hulud activity",
)
git_ref_tag_check = Detection(
    lambda path, file: ".git" in path.parts and "hulud" in file.lower(),
    "Git reference/tag indicates Shai Hulud activity",
)
gh_action_check = Detection(
    lambda path, file: file == "discussion.yaml"
    and path.parts[-2:] == (".github", "workflows"),
    "GitHub discussion workflow detected",
)
gh_workflow_check = Detection(
    lambda path, file: path.parts[-2:] == (".github", "workflows")
    and "hulud" in Path(path).joinpath(file).read_text().lower(),
    "GitHub workflow indicates Shai Hulud activity",
)


def detect_file_ioc(start_dir: Path):
    detections = [
        filename_check,
        package_json_check,
        bun_binary_check,
        hash_checks,
        git_log_check,
        git_ref_tag_check,
        gh_action_check,
        gh_workflow_check,
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
    start_dir: Path = (
        Path(sys.argv[1]).expanduser().resolve() if len(sys.argv) > 1 else Path.home()
    )
    for file_info in detect_file_ioc(start_dir):
        print(json.dumps(file_info))


if __name__ == "__main__":
    main()
