# Capability-Budgeted Dense Specialization

Research workspace for improving Unix-terminal performance per unit of model
capacity in dense language models with fewer than one billion parameters.

The project compares fixed-size post-training with task-aware structural and
deployment compression. It does not treat safety-oriented suppression or
ability loss as a result unless target performance or deployed footprint
improves.

- [Research plan](PLAN.md)
- [Implementation status](IMPLEMENTATION.md)
- [Portable hardware benchmarking guide](HARDWARE.md)
- [Hardware result JSON Schema](hardware-result.schema.json)
- [Experiment manifest JSON Schema](experiment-manifest.schema.json)
- [Per-task result JSON Schema](task-result.schema.json)

## Quick start

The current foundation has no mandatory third-party Python dependencies:

```bash
python -m pip install -e .
cbds prepare \
  --config configs/benchmark-smoke.json \
  --output-dir data/generated/smoke
python -m unittest discover -s tests -v
```

Use `configs/benchmark-plan.json` only when the full 20,250-record semantic
scaffold is wanted. Generated data, run outputs, and model artifacts are
ignored by Git; their cryptographic identities belong in experiment
manifests.

## Status

Executable-foundation stage. Deterministic benchmark scaffolding, frozen
response extraction, sandbox command construction, and schema-validated
experiment accounting are being implemented. Training backends, executable task
verifiers, model downloads, and research results are not yet present. No
experimental result is claimed in this repository.
