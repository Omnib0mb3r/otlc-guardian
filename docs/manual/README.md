# The Guardian manual

The manual is written from the code, one chapter per part of Guardian. It
moves with the code: a change to how a part works edits the chapter that
describes it in the same piece of work.

## Layout

| Path | What it is |
|---|---|
| `chapters/*.html` | The source. One `<section class="chapter">` fragment per file; `00-cover.html` is the cover. The build sorts them by file name. |
| `manual.css` | The stylesheet |
| `build.mjs` | The build |
| `GUARDIAN-MANUAL.html` | Output: the whole manual as one self-contained page |
| `site/` | Output: one page per chapter |

## Build

```
node docs/manual/build.mjs
```

Run it from the repo root after any chapter edit, and commit the chapter
with both outputs. The build fails on an em or en dash, on a link to an id
that no chapter holds, and on an SVG marker used and not defined in the
same file.

## Publish

The manual Michael reads is a private claude.ai artifact, published from
`GUARDIAN-MANUAL.html`.

| Item | Value |
|---|---|
| Title | OTLC Guardian Manual |
| Slug | `9abcfdba-0303-4806-8499-b8f668acdc04` |
| URL | https://claude.ai/artifact/L7FS3qFH8EftTu5FRXmygF |
| First published | 2026-11-12, from commit `f170ed3` |

Every republish goes to that same slug, so the URL never changes. Never
publish the manual as a new artifact.

To republish after a rebuild, with the claude-artifacts tools:

1. `get_artifact` with the slug, and take the `version` it returns.
2. `publish_files` with the slug, that version as `base_version`, and
   `GUARDIAN-MANUAL.html` served as `index.html`. Leave the title and icon
   out so they are kept.

## Where this file does not go

This file stays in `docs/manual/`. It is not in the `files` list of
`package.json`, and `guardian init` does not copy it. The repo's root
`CLAUDE.md` is the wrong place for anything about this repo alone:
`guardian init` and `guardian update` copy that whole file into every
project that installs Guardian.
