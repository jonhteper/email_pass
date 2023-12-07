lint:
	cargo clippy --features serde

lint-legacy:
	cargo clippy --features serde,legacy

test:
	cargo test --features serde

test-legacy:
	cargo test --features serde,legacy