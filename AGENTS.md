# ecrterm

Python library implementing the ZVT 700 protocol between an electronic cash register (ECR) and a payment terminal (PT).
Wirelane fork; the working branch is `py3` (feature branches and PRs target it). Generic workflow rules (branches,
commits, testing, revert-checks) are in the `ai-base` `AGENTS.md`.

## Layout
- `ecrterm/ecr.py` — `ECR` high-level API, `parse_represented_data()` (parses a hex string into a packet)
- `ecrterm/packets/` — APDU parsing/serialization: `apdu.py` (`APDU.parse`, field and bitmap parsing),
  `base_packets.py` (packet classes, e.g. `Completion`, `StatusInformation`, `Abort`), `bitmaps.py` (BMP table),
  `fields.py` (field types, `ParseError`, TLV tag registry), `tlv.py`, `types.py`
- `ecrterm/transmission/` — serial and socket transports
- `ecrterm/tests/` — `unittest` tests, mostly parsing of captured terminal packets as hex strings
- `test_pt.py` — manual example script against a real terminal, not a test

## Commands
CI (GitHub Actions, `.github/workflows/pull_requests.yml`) runs on Python 3.9. Locally:
```
docker run --rm --network=host -v "$PWD":/src -w /src -e PYTHONDONTWRITEBYTECODE=1 python:3.9 bash -c \
  "pip install -q -r ecrterm/requirements.txt && flake8 ecrterm/ && python -m unittest discover -s ecrterm/tests/"
```
Install the requirements before running the tests: without `pyserial` the test modules fail to import and the run
reports loader errors instead of test results.

## Releases and consumers
- `zvt-service` consumes the library via a git tag in its `requirements.txt` (`git+https://github.com/wirelane/ecrterm.git@vX.Y.Z`).
- A release is a version bump of `__version__` in `ecrterm/__init__.py` (`setup.py` reads it from there), usually in
  the feature commit, plus a tag `vX.Y.Z` created and pushed by a human after merge (see `README.md`).

## Parsing gotchas
- Setting a field or bitmap attribute to `None` stores the coerced value (`BCDField` turns it into the string `'None'`).
  To leave a value empty, do not set it.
- Some terminals send BMP 87 (receipt number) without value bytes. `APDU._parse_inner` retries the bitmap parsing with
  that 87 treated as empty (leaving `receipt` unset) only if the normal parse failed directly after an 87, i.e. the
  receipt was the last bitmap parsed. If the retry fails in any way, the original `ParseError` is raised.
