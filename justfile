test:
    cargo hack --workspace --feature-powerset --exclude-features unstable test

lint:
    cargo hack --workspace --feature-powerset --exclude-features unstable clippy
