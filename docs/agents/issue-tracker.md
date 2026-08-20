# Issue tracker: GitHub & Local Markdown

Issues and specs for this repo live as GitHub issues, with local markdown in `.scratch/` supported during early offline development.

## GitHub Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`, filtering comments by `jq` and fetching labels.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

Infer the repo from `git remote -v`; `gh` does this automatically when run inside a clone.

## Local Markdown Conventions (.scratch/)

When working offline or without a remote:
- One feature per directory: `.scratch/<feature-slug>/`
- The spec is `.scratch/<feature-slug>/spec.md`
- Implementation issues are one file per ticket at `.scratch/<feature-slug>/issues/<NN>-<slug>.md`, numbered from `01`.
- Triage state is recorded as a `Status:` line near the top of each issue file (see `docs/agents/triage-labels.md`).
- Comments and conversation history append to the bottom under a `## Comments` heading.

## Pull requests as a triage surface

**PRs as a request surface: no.**

## When a skill says "publish to the issue tracker"

If a `git remote` is configured, create a GitHub issue. Otherwise, create a file under `.scratch/<feature-slug>/`.

## When a skill says "fetch the relevant ticket"

If a number is passed, run `gh issue view <number> --comments`. If a filepath is passed, read the file directly.
