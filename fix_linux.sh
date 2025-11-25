#!/bin/bash
#
# fix_linux.sh
# Executes Linux hardening fixes coming from YAML-based rule engine.
#
# Usage:
#   fix_linux.sh "<RULE_ID>" "<SCRIPT_CONTENT>"
#
# Logs are stored at:
#   /var/log/sys_hardener/fix.log
#

RULE_ID="$1"
SCRIPT_CONTENT="$2"

LOG_DIR="/var/log/sys_hardener"
LOG_FILE="$LOG_DIR/fix.log"

mkdir -p "$LOG_DIR"


log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S')  [$RULE_ID]  $1" | tee -a "$LOG_FILE"
}

log "------------------------------------------------------------"
log "Fix execution started"

# Temporary location to hold the rule script
TMP_SCRIPT="/tmp/fix_${RULE_ID}.sh"

echo "$SCRIPT_CONTENT" > "$TMP_SCRIPT"
chmod +x "$TMP_SCRIPT"

# Execute the fix script
if bash "$TMP_SCRIPT"; then
    log "Fix applied successfully."
else
    log "Fix FAILED. See above for details."
    exit 1
fi

# Cleanup
rm -f "$TMP_SCRIPT"

log "Fix execution completed"
log "------------------------------------------------------------"

exit 0
