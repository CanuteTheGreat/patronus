F=patronus-web/ups,patronus-network/ups
echo "## network ups"; cargo test -p patronus-network --features ups --lib 2>&1 | grep -E "^test .*(ups|svc|packages|sysops|FAILED)|test result|^error" -A3 | grep -E "ups|FAILED|test result|error|panicked" | head -60
echo "## web ups"; cargo test -p patronus-web --features ups 2>&1 | grep -E "ups|FAILED|test result|^error|panicked" | head -60
echo "## firewall"; cargo test -p patronus-firewall 2>&1 | grep -E "ups|FAILED|test result|^error|panicked" | head
echo "## config"; cargo test -p patronus-config 2>&1 | grep -E "FAILED|test result|^error|panicked" | head
echo "## web without ups"; cargo check -p patronus-web --no-default-features 2>&1 | grep -E "^(error|warning)" -A8 | head -30
echo "## cli"; cargo check -p patronus-cli 2>&1 | grep -E "^(error|warning)" -A8 | head -30
echo "## clippy"; cargo clippy -p patronus-network -p patronus-web --features ups -- -D warnings 2>&1 | grep -E "^(error|warning)" -A10 | head -60
echo "## fmt"; cargo fmt --check -p patronus-network -p patronus-web -p patronus-firewall -p patronus-cli 2>&1 | head -20
echo DONE
