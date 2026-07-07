#!/usr/bin/env bash
set -e

PROFILE="${AI_GUARDIAN_PROFILE:-standard}"
SCENARIOS_DIR="/sandbox/scenarios/$PROFILE"

if [ ! -d "$SCENARIOS_DIR" ]; then
  echo "No scenarios found for profile: $PROFILE" >&2
  echo "Available profiles: $(ls /sandbox/scenarios/)" >&2
  exit 1
fi

echo "Running scenarios for profile: $PROFILE"

# Apply the profile config using ai-guardian's own bundled profile templates.
# Writing directly to the user config path works around issue #1501
# (ai-guardian setup --profile fails to write the config in the container).
# The --json flag returns the resolved profile config without writing it,
# so we capture it and write it ourselves.
mkdir -p /sandbox/.config/ai-guardian
ai-guardian setup --create-config --profile "@${PROFILE}" --json 2>/dev/null \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
cfg = data.get('ai_guardian_config', data)
with open('/sandbox/.config/ai-guardian/ai-guardian.json', 'w') as f:
    json.dump(cfg, f, indent=2)
"

for f in "$SCENARIOS_DIR"/*.yaml; do
  echo "=== $f ==="
  ai-guardian dummy-agent --script "$f"
done
