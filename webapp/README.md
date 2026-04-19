# PA00 Webapp

Interactive scaffold for PA00 with a live two-column reduction explorer.

## Run

```bash
cd webapp
npm install
npm run dev
```

## What is implemented in this scaffold

- Foundation toggle: AES / DLP
- Bidirectional mode toggle: Forward (A to B) and Backward (B to A)
- Two-column layout:
	- Build panel: Foundation to A chain with intermediate hex traces
	- Reduce panel: A to B reduction trace using A as a black-box oracle
- Collapsible proof summary panel with theorem and security-chain stubs
- Placeholder rendering for unimplemented steps, including due PA number

## Current scope

- Uses deterministic stub hex outputs for toy parameters (PA00 requirement)
- Reduction routing is table-driven and returns clear unsupported-direction messages
- Live updates are immediate on every input change (foundation, mode, A, B, key, message)

## Next integration step

Replace stub transforms in `src/foundations.ts` and `src/routing.ts` with calls to your real PA implementations via WebAssembly or local API bindings.
