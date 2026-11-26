set -u
export PATH=/usr/local/cargo/bin:$PATH
echo "## fmt"; cargo fmt --all --check 2>&1 | head -5
echo "## network ups"; cargo test -p patronus-network --features ups 2>&1 | grep -E "^test .*FAILED|test result|^error|panicked" | head -30
echo "## web ups"; cargo test -p patronus-web --features ups 2>&1 | grep -E "FAILED|test result|^error|panicked" | head -30
echo "## firewall"; cargo test -p patronus-firewall 2>&1 | grep -E "FAILED|test result|^error|panicked" | head
echo "## config"; cargo test -p patronus-config 2>&1 | grep -E "FAILED|test result|^error|panicked" | head
echo "## cli"; cargo test -p patronus-cli 2>&1 | grep -E "FAILED|test result|^error|panicked" | head
echo "## web without ups"; cargo check -p patronus-web --no-default-features 2>&1 | grep -E "^(error|warning)" -A8 | head -30
echo "## clippy"; cargo clippy -p patronus-network -p patronus-web -p patronus-firewall -p patronus-cli --all-targets --features patronus-web/ups,patronus-network/ups -- -D warnings 2>&1 | grep -E "^(error|warning)" -A10 | head -80
echo DONE
