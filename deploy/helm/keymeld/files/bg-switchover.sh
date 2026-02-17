#!/usr/bin/env bash
#
# Blue/green switchover script for SQLite + Litestream services.
# Called by ArgoCD PreSync hook Jobs with app-specific env vars.
#
# Required env vars (set by Helm template in bg-hook-job.yaml):
#   NAMESPACE      - Kubernetes namespace
#   SERVICE        - Service name to patch selector on
#   DEPLOY_PREFIX  - Deployment name prefix (e.g. "keymeld", deployments are PREFIX-blue/PREFIX-green)
#   CONTAINER      - Container name in deployment spec
#   NEW_IMAGE      - Full image:tag to deploy
#   MOUNT_PATH     - PVC mount path for data directory
#   APP_LABEL      - Value of app.kubernetes.io/name label for pod selectors
#
# Optional env vars (oracle weather data restore):
#   WEATHER_RESTORE_ENABLED - Set to "true" to enable weather parquet restore from S3
#   WEATHER_DATA_DIR        - Directory within MOUNT_PATH containing parquet files
#   WEATHER_S3_BUCKET       - S3 bucket name for weather data
#   WEATHER_S3_REGION       - AWS region for S3 bucket

set -euo pipefail

# Validate required env vars
: "${NAMESPACE:?NAMESPACE is required}"
: "${SERVICE:?SERVICE is required}"
: "${DEPLOY_PREFIX:?DEPLOY_PREFIX is required}"
: "${CONTAINER:?CONTAINER is required}"
: "${NEW_IMAGE:?NEW_IMAGE is required}"
: "${MOUNT_PATH:?MOUNT_PATH is required}"
: "${APP_LABEL:?APP_LABEL is required}"

WEATHER_RESTORE_ENABLED="${WEATHER_RESTORE_ENABLED:-false}"

# Compute total steps based on whether weather restore is enabled
if [[ "$WEATHER_RESTORE_ENABLED" == "true" ]]; then
  TOTAL_STEPS=12
else
  TOTAL_STEPS=11
fi
STEP=0
step() { STEP=$((STEP + 1)); echo "Step ${STEP}/${TOTAL_STEPS}: $1"; }

echo "=== Blue/Green PreSync Switchover ==="
echo "Namespace: $NAMESPACE"
echo "Service: $SERVICE"
echo "New image: $NEW_IMAGE"

# Get current active slot from Service selector
ACTIVE=$(kubectl -n "$NAMESPACE" get svc "$SERVICE" \
  -o jsonpath='{.spec.selector.app\.kubernetes\.io/slot}' 2>/dev/null || echo "")

if [[ -z "$ACTIVE" ]]; then
  echo "No slot selector found on Service. First deploy - initializing."
  echo "Scaling up ${DEPLOY_PREFIX}-blue..."
  kubectl -n "$NAMESPACE" scale deployment "${DEPLOY_PREFIX}-blue" --replicas=1 || true
  echo "Waiting for ${DEPLOY_PREFIX}-blue to be ready..."
  kubectl -n "$NAMESPACE" rollout status deployment "${DEPLOY_PREFIX}-blue" --timeout=300s || true
  echo "Patching Service selector to blue..."
  kubectl -n "$NAMESPACE" patch svc "$SERVICE" --type=json \
    -p '[{"op": "add", "path": "/spec/selector/app.kubernetes.io~1slot", "value": "blue"}]' || true
  echo "Scaling down ${DEPLOY_PREFIX}-green..."
  kubectl -n "$NAMESPACE" scale deployment "${DEPLOY_PREFIX}-green" --replicas=0 || true
  echo "First deploy initialization complete."
  exit 0
fi

if [[ "$ACTIVE" == "blue" ]]; then STANDBY="green"; else STANDBY="blue"; fi

ACTIVE_DEPLOY="${DEPLOY_PREFIX}-${ACTIVE}"
STANDBY_DEPLOY="${DEPLOY_PREFIX}-${STANDBY}"

echo "Active: $ACTIVE ($ACTIVE_DEPLOY)"
echo "Standby: $STANDBY ($STANDBY_DEPLOY)"

CURRENT_IMAGE=$(kubectl -n "$NAMESPACE" get deployment "$ACTIVE_DEPLOY" \
  -o jsonpath="{.spec.template.spec.containers[?(@.name=='$CONTAINER')].image}" 2>/dev/null || echo "")

echo "Current active image: $CURRENT_IMAGE"

if [[ "$CURRENT_IMAGE" == "$NEW_IMAGE" ]]; then
  echo "Active deployment already running $NEW_IMAGE. No switchover needed."
  kubectl -n "$NAMESPACE" scale deployment "$STANDBY_DEPLOY" --replicas=0 2>/dev/null || true
  exit 0
fi

echo ""
echo "=== Starting switchover: $ACTIVE -> $STANDBY ==="

# Step 1: Update standby image
step "Setting $STANDBY_DEPLOY image to $NEW_IMAGE"
kubectl -n "$NAMESPACE" set image "deployment/$STANDBY_DEPLOY" "$CONTAINER=$NEW_IMAGE"

# Step 2: Scale down active so Litestream flushes WAL to S3 on SIGTERM.
# This must happen BEFORE the standby starts, otherwise the standby
# restores stale data from S3 (the active's latest writes haven't
# been synced yet).
step "Scaling down $ACTIVE_DEPLOY (Litestream will flush WAL to S3)"
kubectl -n "$NAMESPACE" scale deployment "$ACTIVE_DEPLOY" --replicas=0

# Step 3: Wait for active pods to fully terminate so Litestream
# completes its S3 sync on shutdown.
step "Waiting for $ACTIVE_DEPLOY pods to terminate"
kubectl -n "$NAMESPACE" wait --for=delete pod \
  -l "app.kubernetes.io/slot=$ACTIVE,app.kubernetes.io/name=$APP_LABEL" \
  --timeout=60s 2>/dev/null || true
echo "$ACTIVE_DEPLOY terminated"

# Step 4: Wait for Litestream S3 sync to propagate.
# The pod is gone but the S3 PUT may still be in-flight or eventually-consistent.
step "Waiting for Litestream S3 sync to propagate"
sleep 10
echo "S3 sync propagation window complete"

# Step 5: Clean standby PVC so the litestream-restore init container
# does a full restore from S3 instead of skipping (it uses -if-db-not-exists).
# Without this, stale DB files on the standby PVC would be used as-is.
step "Cleaning standby PVC (${DEPLOY_PREFIX}-${STANDBY})"
CLEANUP_POD="pvc-cleanup-${STANDBY}-$(date +%s)"
CLEANUP_CMD="echo Cleaning PVC files...; find $MOUNT_PATH -type f -name '*.db' -exec rm -fv {} +; find $MOUNT_PATH -type f -name '*.db-shm' -exec rm -fv {} +; find $MOUNT_PATH -type f -name '*.db-wal' -exec rm -fv {} +; find $MOUNT_PATH -type f -name '*.sqlite' -exec rm -fv {} +; find $MOUNT_PATH -type f -name '*.sqlite-shm' -exec rm -fv {} +; find $MOUNT_PATH -type f -name '*.sqlite-wal' -exec rm -fv {} +; find $MOUNT_PATH -type d -name '*-litestream' -exec rm -rfv {} + 2>/dev/null; echo PVC cleaned"
printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"%s"},"spec":{"restartPolicy":"Never","containers":[{"name":"cleanup","image":"alpine:latest","command":["sh","-c","%s"],"volumeMounts":[{"name":"data","mountPath":"%s"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"%s"}}]}}' \
  "$CLEANUP_POD" "$CLEANUP_CMD" "$MOUNT_PATH" "${DEPLOY_PREFIX}-${STANDBY}" \
  | kubectl -n "$NAMESPACE" apply -f - 2>/dev/null || echo "WARNING: Failed to create cleanup pod"
echo "Waiting for cleanup pod to complete..."
for i in $(seq 1 60); do
  PHASE=$(kubectl -n "$NAMESPACE" get pod "$CLEANUP_POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
  if [[ "$PHASE" == "Succeeded" || "$PHASE" == "Failed" ]]; then
    echo "Cleanup pod finished with phase: $PHASE"
    break
  fi
  sleep 1
done
kubectl -n "$NAMESPACE" logs "$CLEANUP_POD" 2>/dev/null || true
kubectl -n "$NAMESPACE" delete pod "$CLEANUP_POD" --ignore-not-found 2>/dev/null || true

# Step 6: Verify standby PVC is clean. If stale DB files remain,
# the litestream-restore init container will skip restore (-if-db-not-exists)
# and the standby starts with old/corrupt data.
step "Verifying standby PVC is clean"
VERIFY_POD="pvc-verify-${STANDBY}-$(date +%s)"
printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"%s"},"spec":{"restartPolicy":"Never","containers":[{"name":"verify","image":"alpine:latest","command":["sh","-c","find %s -name '"'"'*.db'"'"' -o -name '"'"'*.sqlite'"'"' -o -name '"'"'*-litestream'"'"' 2>/dev/null | wc -l"],"volumeMounts":[{"name":"data","mountPath":"%s"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"%s"}}]}}' \
  "$VERIFY_POD" "$MOUNT_PATH" "$MOUNT_PATH" "${DEPLOY_PREFIX}-${STANDBY}" \
  | kubectl -n "$NAMESPACE" apply -f - 2>/dev/null || echo "WARNING: Failed to create verify pod"
for i in $(seq 1 30); do
  PHASE=$(kubectl -n "$NAMESPACE" get pod "$VERIFY_POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
  if [[ "$PHASE" == "Succeeded" || "$PHASE" == "Failed" ]]; then break; fi
  sleep 1
done
STALE_FILES=$(kubectl -n "$NAMESPACE" logs "$VERIFY_POD" 2>/dev/null | tr -d '[:space:]')
kubectl -n "$NAMESPACE" delete pod "$VERIFY_POD" --ignore-not-found 2>/dev/null || true
if [[ -n "$STALE_FILES" && "$STALE_FILES" -gt 0 ]] 2>/dev/null; then
  echo "ERROR: PVC cleanup failed: $STALE_FILES database files still present on ${DEPLOY_PREFIX}-${STANDBY}"
  echo "Rolling back: scaling up previous active"
  kubectl -n "$NAMESPACE" scale deployment "$ACTIVE_DEPLOY" --replicas=1
  exit 1
fi
echo "Standby PVC is clean, restore will fetch fresh data from S3"

# Step 7: Scale up standby (triggers Litestream restore from fresh S3 data)
step "Scaling up $STANDBY_DEPLOY (will restore DB from S3)"
kubectl -n "$NAMESPACE" scale deployment "$STANDBY_DEPLOY" --replicas=1

# Step 8: Wait for readiness
step "Waiting for $STANDBY_DEPLOY to be ready..."
if ! kubectl -n "$NAMESPACE" rollout status deployment "$STANDBY_DEPLOY" --timeout=300s; then
  echo "ERROR: Standby deployment failed readiness check"
  echo "Rolling back: scaling down standby, scaling up previous active"
  kubectl -n "$NAMESPACE" scale deployment "$STANDBY_DEPLOY" --replicas=0
  kubectl -n "$NAMESPACE" scale deployment "$ACTIVE_DEPLOY" --replicas=1
  exit 1
fi

# Step 9: Verify restored database integrity before routing traffic.
# Uses a temporary pod pinned to the standby node for RWO PVC access.
step "Verifying database integrity on standby"
STANDBY_NODE=$(kubectl -n "$NAMESPACE" get pod \
  -l "app.kubernetes.io/slot=$STANDBY,app.kubernetes.io/name=$APP_LABEL" \
  -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)
INTEGRITY_POD="db-integrity-${STANDBY}-$(date +%s)"
INTEGRITY_CMD="apk add --no-cache sqlite >/dev/null 2>&1 && find $MOUNT_PATH -name '*.db' -o -name '*.sqlite' | while read db; do result=\$(sqlite3 \"\$db\" 'PRAGMA quick_check;' 2>&1); if [ \"\$result\" != 'ok' ]; then echo \"FAILED:\$db:\$result\"; fi; done; echo DONE"
printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"%s"},"spec":{"nodeName":"%s","restartPolicy":"Never","containers":[{"name":"check","image":"alpine:latest","command":["sh","-c","%s"],"volumeMounts":[{"name":"data","mountPath":"%s"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"%s"}}]}}' \
  "$INTEGRITY_POD" "$STANDBY_NODE" "$INTEGRITY_CMD" "$MOUNT_PATH" "${DEPLOY_PREFIX}-${STANDBY}" \
  | kubectl -n "$NAMESPACE" apply -f - 2>/dev/null || echo "WARNING: Failed to create integrity check pod"
for i in $(seq 1 60); do
  PHASE=$(kubectl -n "$NAMESPACE" get pod "$INTEGRITY_POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
  if [[ "$PHASE" == "Succeeded" || "$PHASE" == "Failed" ]]; then break; fi
  sleep 1
done
DB_INTEGRITY=$(kubectl -n "$NAMESPACE" logs "$INTEGRITY_POD" 2>/dev/null)
kubectl -n "$NAMESPACE" delete pod "$INTEGRITY_POD" --ignore-not-found 2>/dev/null || true

if echo "$DB_INTEGRITY" | grep -q "FAILED:"; then
  echo "WARNING: Integrity check failed, attempting REINDEX on affected databases..."

  # Scale down standby for exclusive PVC access during repair
  kubectl -n "$NAMESPACE" scale deployment "$STANDBY_DEPLOY" --replicas=0
  kubectl -n "$NAMESPACE" wait --for=delete pod \
    -l "app.kubernetes.io/slot=$STANDBY,app.kubernetes.io/name=$APP_LABEL" \
    --timeout=60s 2>/dev/null || true

  REPAIR_POD="db-repair-${STANDBY}-$(date +%s)"
  REPAIR_CMD="apk add --no-cache sqlite >/dev/null 2>&1 && find $MOUNT_PATH -name '*.db' -o -name '*.sqlite' | while read db; do sqlite3 \"\$db\" 'REINDEX; VACUUM;' 2>&1; result=\$(sqlite3 \"\$db\" 'PRAGMA integrity_check;' 2>&1); if [ \"\$result\" != 'ok' ]; then echo \"FAILED:\$db:\$result\"; fi; done; echo DONE"
  printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"%s"},"spec":{"nodeName":"%s","restartPolicy":"Never","containers":[{"name":"repair","image":"alpine:latest","command":["sh","-c","%s"],"volumeMounts":[{"name":"data","mountPath":"%s"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"%s"}}]}}' \
    "$REPAIR_POD" "$STANDBY_NODE" "$REPAIR_CMD" "$MOUNT_PATH" "${DEPLOY_PREFIX}-${STANDBY}" \
    | kubectl -n "$NAMESPACE" apply -f - 2>/dev/null || true
  for i in $(seq 1 60); do
    PHASE=$(kubectl -n "$NAMESPACE" get pod "$REPAIR_POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
    if [[ "$PHASE" == "Succeeded" || "$PHASE" == "Failed" ]]; then break; fi
    sleep 1
  done
  REPAIR_RESULT=$(kubectl -n "$NAMESPACE" logs "$REPAIR_POD" 2>/dev/null)
  kubectl -n "$NAMESPACE" delete pod "$REPAIR_POD" --ignore-not-found 2>/dev/null || true

  if echo "$REPAIR_RESULT" | grep -q "FAILED:"; then
    echo "ERROR: Database integrity check failed after REINDEX"
    echo "$REPAIR_RESULT" | grep "FAILED:"
    echo "Rolling back: scaling up previous active"
    kubectl -n "$NAMESPACE" scale deployment "$ACTIVE_DEPLOY" --replicas=1
    exit 1
  fi
  echo "REINDEX repaired integrity issues, scaling standby back up"
  kubectl -n "$NAMESPACE" scale deployment "$STANDBY_DEPLOY" --replicas=1
  if ! kubectl -n "$NAMESPACE" rollout status deployment "$STANDBY_DEPLOY" --timeout=300s; then
    echo "ERROR: Standby failed to restart after REINDEX, rolling back"
    kubectl -n "$NAMESPACE" scale deployment "$STANDBY_DEPLOY" --replicas=0
    kubectl -n "$NAMESPACE" scale deployment "$ACTIVE_DEPLOY" --replicas=1
    exit 1
  fi
else
  echo "Database integrity check passed"
fi

# Conditional step: Weather parquet data restore (oracle only)
if [[ "$WEATHER_RESTORE_ENABLED" == "true" ]]; then
  : "${WEATHER_DATA_DIR:?WEATHER_DATA_DIR required when WEATHER_RESTORE_ENABLED=true}"
  : "${WEATHER_S3_BUCKET:?WEATHER_S3_BUCKET required when WEATHER_RESTORE_ENABLED=true}"
  : "${WEATHER_S3_REGION:?WEATHER_S3_REGION required when WEATHER_RESTORE_ENABLED=true}"

  step "Checking weather data on standby PVC"
  WEATHER_CHECK_POD="weather-check-${STANDBY}-$(date +%s)"
  printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"%s"},"spec":{"nodeName":"%s","restartPolicy":"Never","containers":[{"name":"check","image":"alpine:latest","command":["sh","-c","find %s -name '"'"'*.parquet'"'"' 2>/dev/null | wc -l"],"volumeMounts":[{"name":"data","mountPath":"%s"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"%s"}}]}}' \
    "$WEATHER_CHECK_POD" "$STANDBY_NODE" "$WEATHER_DATA_DIR" "$MOUNT_PATH" "${DEPLOY_PREFIX}-${STANDBY}" \
    | kubectl -n "$NAMESPACE" apply -f - 2>/dev/null || echo "WARNING: Failed to create weather check pod"
  for i in $(seq 1 30); do
    PHASE=$(kubectl -n "$NAMESPACE" get pod "$WEATHER_CHECK_POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
    if [[ "$PHASE" == "Succeeded" || "$PHASE" == "Failed" ]]; then break; fi
    sleep 1
  done
  PARQUET_COUNT=$(kubectl -n "$NAMESPACE" logs "$WEATHER_CHECK_POD" 2>/dev/null | tr -d '[:space:]')
  kubectl -n "$NAMESPACE" delete pod "$WEATHER_CHECK_POD" --ignore-not-found 2>/dev/null || true

  if [[ -n "$PARQUET_COUNT" && "$PARQUET_COUNT" -gt 0 ]] 2>/dev/null; then
    echo "Weather data present ($PARQUET_COUNT parquet files). Skipping S3 restore."
  else
    echo "No weather data found on standby PVC. Restoring from S3..."

    # Scale down standby to release RWO PVC for the restore pod
    kubectl -n "$NAMESPACE" scale deployment "$STANDBY_DEPLOY" --replicas=0
    kubectl -n "$NAMESPACE" wait --for=delete pod \
      -l "app.kubernetes.io/slot=$STANDBY,app.kubernetes.io/name=$APP_LABEL" \
      --timeout=60s 2>/dev/null || true

    RESTORE_POD="weather-restore-${STANDBY}-$(date +%s)"
    RESTORE_CMD="mkdir -p ${WEATHER_DATA_DIR} && aws s3 sync s3://${WEATHER_S3_BUCKET}/weather_data/ ${WEATHER_DATA_DIR}/ --region ${WEATHER_S3_REGION} --only-show-errors && TOTAL=\$(find ${WEATHER_DATA_DIR} -name '*.parquet' 2>/dev/null | wc -l) && echo \"Restored \$TOTAL parquet files\""
    printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"%s"},"spec":{"nodeName":"%s","restartPolicy":"Never","containers":[{"name":"restore","image":"amazon/aws-cli:latest","command":["sh","-c","%s"],"volumeMounts":[{"name":"data","mountPath":"%s"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"%s"}}]}}' \
      "$RESTORE_POD" "$STANDBY_NODE" "$RESTORE_CMD" "$MOUNT_PATH" "${DEPLOY_PREFIX}-${STANDBY}" \
      | kubectl -n "$NAMESPACE" apply -f - 2>/dev/null || echo "WARNING: Failed to create weather restore pod"

    RESTORE_OK=false
    for i in $(seq 1 300); do
      PHASE=$(kubectl -n "$NAMESPACE" get pod "$RESTORE_POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
      if [[ "$PHASE" == "Succeeded" ]]; then RESTORE_OK=true; break; fi
      if [[ "$PHASE" == "Failed" ]]; then break; fi
      sleep 1
    done
    kubectl -n "$NAMESPACE" logs "$RESTORE_POD" 2>/dev/null || true
    kubectl -n "$NAMESPACE" delete pod "$RESTORE_POD" --ignore-not-found 2>/dev/null || true

    if [[ "$RESTORE_OK" == "true" ]]; then
      echo "Weather data restore from S3 completed successfully"
    else
      echo "WARNING: Weather data restore failed. Run 'just restore-oracle-data' manually after switchover."
    fi

    # Scale standby back up
    kubectl -n "$NAMESPACE" scale deployment "$STANDBY_DEPLOY" --replicas=1
    if ! kubectl -n "$NAMESPACE" rollout status deployment "$STANDBY_DEPLOY" --timeout=300s; then
      echo "ERROR: Standby failed to restart after weather restore, rolling back"
      kubectl -n "$NAMESPACE" scale deployment "$STANDBY_DEPLOY" --replicas=0
      kubectl -n "$NAMESPACE" scale deployment "$ACTIVE_DEPLOY" --replicas=1
      exit 1
    fi
  fi
fi

# Flip Service selector (503 window ends)
step "Flipping Service selector to $STANDBY"
kubectl -n "$NAMESPACE" patch svc "$SERVICE" --type=json \
  -p "[{\"op\": \"replace\", \"path\": \"/spec/selector/app.kubernetes.io~1slot\", \"value\": \"$STANDBY\"}]"

# Verify
NEW_ACTIVE=$(kubectl -n "$NAMESPACE" get svc "$SERVICE" \
  -o jsonpath='{.spec.selector.app\.kubernetes\.io/slot}')
echo "Service now pointing to: $NEW_ACTIVE"

# Scale down old active
step "Scaling down old active $ACTIVE_DEPLOY"
kubectl -n "$NAMESPACE" scale deployment "$ACTIVE_DEPLOY" --replicas=0 2>/dev/null || true

echo ""
echo "=== Switchover complete ==="
echo "Active: $STANDBY ($STANDBY_DEPLOY) running $NEW_IMAGE"
echo "Standby: $ACTIVE ($ACTIVE_DEPLOY) scaled to 0"
