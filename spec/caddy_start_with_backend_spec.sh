Describe 'caddy-start-with-backend'
  script='support/caddy-start-with-backend'

  setup() {
    test_tmp_dir="$(mktemp -d)"
    export CADDY_TEST_EVENTS="$test_tmp_dir/events"
    export PATH="$SHELLSPEC_PROJECT_ROOT/spec/fixtures:$PATH"
    : >"$CADDY_TEST_EVENTS"
  }

  cleanup() {
    rm -rf "$test_tmp_dir"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'requires a backend command after the separator'
    When run script "$script"
    The status should equal 64
    The stderr should include 'usage:'
  End

  It 'does not start Caddy when the backend exits before readiness'
    export CADDY_TEST_BACKEND_MODE=exit_before_ready

    When run script "$script" -- fake-backend
    The status should equal 23
    The stdout should include 'Waiting for backend readiness'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_started'
    The contents of file "$CADDY_TEST_EVENTS" should not include 'caddy_started'
  End

  It 'waits for the backend readiness file before starting Caddy'
    export CADDY_TEST_BACKEND_MODE=delayed_ready
    export CADDY_TEST_CADDY_MODE=exit

    When run script "$script" -- fake-backend
    The status should equal 29
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_checked_before_ready'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_received_ready_file'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_ready'
    The contents of file "$CADDY_TEST_EVENTS" should not include 'caddy_started_before_ready'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_started'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_term'
  End

  It 'supports the legacy readiness URL and accepts a non-error HTTP response'
    export CADDY_TEST_BACKEND_MODE=wait
    export CADDY_TEST_CURL_MODE=redirect
    export CADDY_TEST_CADDY_MODE=exit
    export CADDY_TEST_LEGACY_MODE=true

    When run script "$script" 'http://127.0.0.1:3000/_up' -- fake-backend
    The status should equal 29
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_missing_ready_file'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_started'
  End

  It 'supports the legacy readiness URL and rejects an HTTP error'
    export CADDY_TEST_BACKEND_MODE=exit_before_ready
    export CADDY_TEST_CURL_MODE=client_error
    export CADDY_TEST_LEGACY_MODE=true

    When run script "$script" 'http://127.0.0.1:3000/_up' -- fake-backend
    The status should equal 23
    The stdout should include 'Waiting for backend readiness'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_missing_ready_file'
    The contents of file "$CADDY_TEST_EVENTS" should not include 'caddy_started'
  End

  It 'terminates Caddy when the backend exits after readiness'
    export CADDY_TEST_BACKEND_MODE=exit_after_ready
    export CADDY_TEST_CADDY_MODE=wait

    When run script "$script" -- fake-backend
    The status should equal 23
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_started'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_term'
  End

  It 'terminates the backend when Caddy exits'
    export CADDY_TEST_BACKEND_MODE=wait
    export CADDY_TEST_CADDY_MODE=exit

    When run script "$script" -- fake-backend
    The status should equal 29
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_started'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_term'
  End

  It 'forwards SIGTERM and stops both children'
    export CADDY_TEST_BACKEND_MODE=wait
    export CADDY_TEST_CADDY_MODE=wait

    When run command ruby spec/fixtures/send_signal.rb "$script" TERM
    The status should equal 143
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_term'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_term'
  End

  It 'forwards SIGINT and stops both children'
    export CADDY_TEST_BACKEND_MODE=wait
    export CADDY_TEST_CADDY_MODE=wait

    When run command ruby spec/fixtures/send_signal.rb "$script" INT
    The status should equal 130
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_term'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_term'
  End

  It 'stops the backend and never starts Caddy after the fixed readiness deadline'
    export CADDY_TEST_BACKEND_MODE=never_ready

    When run script "$script" -- fake-backend
    The status should equal 124
    The stdout should include 'Waiting for backend readiness'
    The stderr should include 'Backend readiness timed out after 45 seconds'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_term'
    The contents of file "$CADDY_TEST_EVENTS" should not include 'caddy_started'
  End
End
