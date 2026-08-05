#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="${repo_root}/docker-compose.oss-e2e.yml"
project="buzz-oss-e2e"
scenario_ids=(A01 D01 D02 D03 D04 L01 L02 L03 R01 O501 P01)

export DATABASE_URL="postgres://buzz:buzz_oss_e2e@127.0.0.1:5546/buzz" # sadscan:disable np.postgres.1
export BUZZ_TEST_DATABASE_URL="${DATABASE_URL}"
export REDIS_URL="redis://127.0.0.1:6546"
export S3_ENDPOINT="http://127.0.0.1:9546"
export S3_ACCESS_KEY="buzz_oss_e2e"
export S3_SECRET_KEY="buzz_oss_e2e_synthetic_secret"
export S3_BUCKET="buzz-media"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

compose() {
  docker compose --project-name "${project}" --file "${compose_file}" "$@"
}

cargo_test() {
  "${repo_root}/bin/cargo" test "$@"
}

setup() {
  compose up --detach --wait postgres redis minio
  compose run --rm minio-init
  compose ps
}

run_scenario() {
  local scenario_id="${1:?scenario ID is required}"
  case "${scenario_id}" in
    A01)
      cargo_test -p buzz-auth current_allow_returns_request_scoped_snapshot
      ;;
    D01)
      cargo_test -p buzz-auth provider_unavailability_never_falls_back_to_allow
      ;;
    D02)
      cargo_test -p buzz-relay duplicate_or_unknown_domains_fail_closed
      ;;
    D03)
      cargo_test -p buzz-auth stale_and_future_provider_decisions_deny
      ;;
    D04)
      cargo_test -p buzz-auth mismatched_embedded_proof_domain_fails_before_authority_io
      ;;
    L01)
      cargo_test -p buzz-db principal_can_be_disabled_before_first_enrollment -- --ignored
      ;;
    L02)
      cargo_test -p buzz-auth direct_lease_carries_binding_and_earliest_application_expiry
      ;;
    L03)
      cargo_test -p buzz-relay projection_worker_retries_after_restart_and_fans_out_canonical_withdrawal -- --ignored
      ;;
    R01)
      cargo_test -p buzz-relay restart_bootstraps_full_state_before_readiness
      ;;
    O501)
      cargo_test -p buzz-relay --test o5_operator_postgres
      cargo_test -p buzz-db postgres_o5_outbox_rollback_delivery_restore_and_capacity_are_non_vacuous
      ;;
    P01)
      cargo_test -p buzz-relay --test o5_operator_surface planted_canaries_never_cross_response_logs_or_metrics
      cargo_test -p buzz-db postgres_operator_lifecycle_is_atomic_idempotent_and_serialized
      ;;
    *)
      printf 'unknown scenario: %s\nvalid scenarios: %s\n' \
        "${scenario_id}" "${scenario_ids[*]}" >&2
      return 64
      ;;
  esac
}

usage() {
  cat <<'USAGE'
usage: scripts/oss-e2e.sh setup|run|reset|stop|status|scenario ID

All services, credentials, fixtures, and identifiers are local and synthetic.
The lifecycle operator surface is constructed only inside its explicit tests;
the stock relay router remains unchanged.
USAGE
}

command_name="${1:-}"
case "${command_name}" in
  setup)
    setup
    ;;
  run)
    setup
    for scenario_id in "${scenario_ids[@]}"; do
      printf '\n[oss-e2e] scenario %s\n' "${scenario_id}"
      run_scenario "${scenario_id}"
    done
    ;;
  reset)
    compose down --volumes --remove-orphans
    setup
    ;;
  stop)
    compose down --remove-orphans
    ;;
  status)
    compose ps
    ;;
  scenario)
    setup
    run_scenario "${2:-}"
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac
