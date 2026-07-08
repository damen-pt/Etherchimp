# Vendored third-party libraries

All libraries in this directory are vendored verbatim from their published
distributions so the app runs fully offline / airgapped (no CDN fetches).

| File | Package | Version | License | Source |
|---|---|---|---|---|
| `vis-network.min.js` | vis-network | (see file header) | Apache-2.0 / MIT dual | https://github.com/visjs/vis-network |
| `three.min.js` | three | (see file header) | MIT | https://github.com/mrdoob/three.js |
| `cosmos-graph.min.js` | @cosmos.gl/graph | 3.1.0 | MIT | https://github.com/cosmosgl/graph |

## @cosmos.gl/graph notes

- Taken from the npm package's `dist/index.min.js` (the `jsdelivr` entry): a
  self-contained UMD bundle exposing the global `Cosmos` — its dependencies
  (luma.gl © OpenJS Foundation, MIT; d3-* © Mike Bostock, ISC; gl-matrix, MIT;
  dompurify, Apache-2.0/MPL-2.0) are compiled in.
- Upstream license text: https://github.com/cosmosgl/graph/blob/main/LICENCE
  (MIT, © cosmos.gl authors).

To update: `npm pack @cosmos.gl/graph`, extract, verify `dist/index.min.js`
has no external `import`/`require` statements, prepend the header comment, and
replace `cosmos-graph.min.js`. Bump the version here and in the file header.
