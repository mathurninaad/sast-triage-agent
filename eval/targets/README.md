# Evaluation targets

Third-party vulnerable apps we scan. They are cloned here, not committed
(see .gitignore). Each one is pinned to a commit so results are reproducible.

| Target | Repo | Commit |
| --- | --- | --- |
| pygoat | https://github.com/adeyosemanputra/pygoat | 2aa4cc14f251e4a780e94e200aed6b36a5b15c21 |

```bash
git clone https://github.com/adeyosemanputra/pygoat.git eval/targets/pygoat
git -C eval/targets/pygoat checkout 2aa4cc14f251e4a780e94e200aed6b36a5b15c21
```
