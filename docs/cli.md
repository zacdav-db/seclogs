# CLI

```
seclog-cli gen --config <file> --output <dir>
               [--max-seconds N] [--max-events N]
               [--gen-workers N] [--writer-shards N]

seclog-cli actors --config <file> --output <file>
```

Notes:
- `--gen-workers 0` uses available CPU cores for generation.
- `--writer-shards 0` uses up to 4 writer threads (sharded by account+region).
