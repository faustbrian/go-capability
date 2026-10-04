# V2 exported API baseline

`baseline.txt` is generated export data, not a textual API list. It covers the
actual exported contract of all seven packages in the root
`github.com/faustbrian/go-capability/v2` module, including the retained facades,
explicit issuer ownership/selection, issuer-scoped consumption, durable
migration and finite memory options. It is the new v2 source baseline, not a
claim that those changes are compatible with the unversioned v1 module or that
a v2 release has been published. Prior baseline content remains in Git history.

The repository API gate uses Go 1.27 and the pinned
`golang.org/x/exp/cmd/apidiff@v0.0.0-20260718201538-764159d718ef` tool in module
mode. From the repository root, generation is:

```sh
go run golang.org/x/exp/cmd/apidiff@v0.0.0-20260718201538-764159d718ef -m -w api/baseline.txt github.com/faustbrian/go-capability/v2
```

Baseline regeneration requires review of the complete changed exported
contract; rewriting old import strings in an archive is not generation.
The API comparison guards subsequent incompatible v2 source changes, while
wire, error behavior, defaults and migration semantics also require focused
behavioral evidence. See [compatibility policy](../COMPATIBILITY.md) and
[consumer adoption](../docs/adoption.md#module-and-import-paths-v2-source).
