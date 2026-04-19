# Team Sequential Workflow

## One-time setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m pois.cli init
```

## Daily flow for each teammate

1. Pull latest code.
2. Check status:

```bash
python -m pois.cli status
```

3. Claim next assignment owned by you (if dependencies are complete):

```bash
python -m pois.cli next --member Kushal
```

4. Implement in `src/pois/assignments/paNN.py` and related files.
5. Run local tests/demos.
6. Mark complete:

```bash
python -m pois.cli complete --member Kushal --task PA01
```

## Conflict minimization rule

- One group member should actively work on only one claimed task at a time.
- Do not edit another member's PA files unless requested.
- Keep shared interfaces backward-compatible.

## Member names to use with CLI

- Diganta
- Kushal
- Nilkanta
- Rohit
- Srinjoy
