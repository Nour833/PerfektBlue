# Module and profile authoring

Profiles are JSON documents installed under `perfektblue/data/profiles` or loaded from a future
operator-managed profile directory. Every rule has a field, operator, expected value, positive
weight, and optional `required` flag.

Profile scores are the percentage of matched rule weight. A failed required rule forces the
score to zero. Names and aliases should have lower weights than manufacturer data and
protocol-specific evidence.

Modules inherit `AssessmentModule` and provide a `ModuleManifest` plus an asynchronous `run`
method. Active modules must:

- Name exact supported profiles.
- Require a high profile confidence.
- Declare services, side effects, risk, and cleanup.
- Derive target values from evidence or the profile.
- Use inert canaries before any stronger verification.
- Return confirmed findings only with stored verification evidence.
- Include vulnerable and patched fixtures.

Register an external module in its `pyproject.toml`:

```toml
[project.entry-points."perfektblue.modules"]
vendor-module = "vendor_package.module:VendorModule"
```

Run `perfektblue profiles validate` and `perfektblue modules validate` before publishing.

