- **`/go` now gates PR execution by source and immutable head SHA.** External forks receive a static
  safety review before a collaborator may promote one revision to isolated CI testing; Dependabot
  remains dynamically tested, and Kimi uses a no-network container shell for both untrusted classes.
