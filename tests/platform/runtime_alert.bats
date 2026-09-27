#!/usr/bin/env bats
# Runtime detection seen in Grafana, live: `task demo:runtime-shell` runs a shell in a workload container and the
# Kubescape alert it raises is returned by Grafana's VictoriaLogs datasource within 2 minutes of the task's start.

bats_require_minimum_version 1.5.0

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
load grafana

ALERT_WINDOW_SECONDS=120
POLL_SECONDS=5
HARBOR_HOST=harbor.127.0.0.1.nip.io
TARGET_LINE_RE='^runtime-shell target: ([a-z0-9-]+)/([a-z0-9.-]+)/([a-z0-9-]+)$'
# A shell process named in the alert text (`Unexpected process launched: sh with PID …`, `Process (sh) …`).
SHELL_RE='(^|[ (/:"])(sh|bash|dash|ash|busybox)([ )"]|$)'

fail() {
  echo "$*" >&2
  return 1
}

setup_file() {
  grafana_setup_file
}

setup() {
  grafana_setup
}

# Kubescape alert rows about container $3 of pod $1/$2 raised at or after $4 (epoch ms), from the /api/ds/query
# response in HTTP_BODY, as a JSON array of {time, text} on stdout.
alert_rows() {
  jq -c --arg ns "$1" --arg pod "$2" --arg container "$3" --argjson since "$4" "$GRAFANA_JQ"'
    [rows[] | {time: ([.[] | select(.type == "time") | .value] | first // 0),
        text: ([.[] | .value, (.labels | tostring)] | map(tostring) | join(" "))}
      | select(.time >= $since)
      | select(.text | contains($pod) and contains($ns) and contains($container))]' "$HTTP_BODY"
}

@test "runtime shell alert is visible in Grafana through VictoriaLogs within 2 minutes" {
  type="$(grafana_datasource_type "$VL_DATASOURCE_UID")" || return 1
  [ "$type" = "$VL_DATASOURCE_TYPE" ] ||
    fail "Grafana datasource $VL_DATASOURCE_UID has type '$type', not the VictoriaLogs plugin $VL_DATASOURCE_TYPE"

  start="$(date +%s)"
  run --separate-stderr bash -c "cd '$REPO_ROOT' && timeout $ALERT_WINDOW_SECONDS task demo:runtime-shell"
  [ "$status" -eq 0 ] || fail "task demo:runtime-shell exited $status: $(tail -n 5 <<<"$stderr") $(tail -n 5 <<<"$output")"
  target="$(grep -E "$TARGET_LINE_RE" <<<"$output" | tail -n 1)"
  [[ "$target" =~ $TARGET_LINE_RE ]] ||
    fail "task demo:runtime-shell printed no 'runtime-shell target: <namespace>/<pod>/<container>' line: $(tail -n 5 <<<"$output")"
  namespace="${BASH_REMATCH[1]}" pod="${BASH_REMATCH[2]}" container="${BASH_REMATCH[3]}"

  kubectl get namespace "$namespace" -l "$WORKLOAD_LABEL" -o name | grep -q . ||
    fail "target namespace $namespace is not labelled $WORKLOAD_LABEL: the shell did not run in a workload container"
  image="$(kubectl -n "$namespace" get pod "$pod" -o json |
    jq -r --arg c "$container" '.spec.containers[] | select(.name == $c) | .image')"
  [[ "$image" == "$HARBOR_HOST/"*@sha256:* ]] ||
    fail "target container $namespace/$pod/$container runs '$image', not a Harbor digest reference"

  # LogsQL field filters on the node-agent alert JSON, flattened by VictoriaLogs.
  jq -n --arg ns "$namespace" --arg pod "$pod" --arg c "$container" '{
      expr: "RuleID:* AND RuntimeK8sDetails.namespace:=\($ns | @json) AND RuntimeK8sDetails.podName:=\($pod | @json) AND RuntimeK8sDetails.containerName:=\($c | @json)",
      queryType: "instant", maxLines: 100}' >"$BATS_TEST_TMPDIR/alert-query.json"

  deadline=$((start + ALERT_WINDOW_SECONDS))
  while :; do
    grafana_ds_query "$VL_DATASOURCE_UID" "$BATS_TEST_TMPDIR/alert-query.json" "$((start * 1000 - 60000))" \
      "$(($(date +%s) * 1000))" || return 1
    alerts="$(alert_rows "$namespace" "$pod" "$container" "$((start * 1000))")"
    shell_alerts="$(jq -c --arg re "$SHELL_RE" '[.[] | select(.text | test($re))]' <<<"$alerts")"
    [ "$(jq length <<<"$shell_alerts")" -eq 0 ] || break
    [ "$(date +%s)" -lt "$deadline" ] ||
      fail "no Kubescape runtime alert naming a shell process in $namespace/$pod/$container reached Grafana through VictoriaLogs within ${ALERT_WINDOW_SECONDS}s of the task's start ($(jq length <<<"$alerts") alert row(s) for that container since then: $(jq -c '.[0].text // "" | .[0:300]' <<<"$alerts"))"
    sleep "$POLL_SECONDS"
  done
}
