# PA00-PA20 Webapp

Interactive demo shell for the assignment chain. PA00 keeps the live reduction explorer scaffold, while the later assignments are wired into the current backend panels.

## Run

```bash
cd webapp
npm install
npm run dev
```

## What is implemented in this webapp

- Top-level assignment tabs for PA00-PA20
- Foundation toggle: AES / DLP
- Bidirectional mode toggle: Forward (A to B) and Backward (B to A)
	- Two-column layout for the PA00 explorer:
	- Build panel: Foundation to A chain with intermediate hex traces
	- Reduce panel: A to B reduction trace using A as a black-box oracle
- Dedicated PA16-PA20 crypto and MPC panels backed by the Python demos
- Collapsible proof summary panel with theorem and security-chain stubs
- Placeholder rendering for unimplemented steps, including due PA number

## Current scope

- Uses deterministic stub hex outputs for toy parameters in the PA00 explorer
- Reduction routing is table-driven and returns clear unsupported-direction messages
- Live updates are immediate on every input change (foundation, mode, A, B, key, message)
- PA16-PA20 are shown as separate tabs with their own assignment-specific controls and notes

## Next integration step

Keep the PA00 explorer aligned with the assignment chain and extend the demo polish as needed when later assignments change.
