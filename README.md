# Domain List

A list of domains applicable to surge and clash, generated based on [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community).

The generated files under `public/` are committed so deployment builds do not
need to clone the upstream data repository. Run `npm run generate` after
checking out `v2fly/domain-list-community` at `domain-list-community/`; run
`npm run build` to validate the committed static output.

## Usage

- https://domain-list.nosec.me/surge/{name}.txt
- https://domain-list.nosec.me/clash/{name}.txt
- https://domain-list.nosec.me/manifest.json

## Examples

- https://domain-list.nosec.me/surge/github.txt
- https://domain-list.nosec.me/clash/github.txt
