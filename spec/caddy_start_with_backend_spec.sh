Describe 'caddy-start-with-backend'
  script='support/caddy-start-with-backend'

  setup() {
    test_tmp_dir="$(mktemp -d)"
    export CADDY_TEST_EVENTS="$test_tmp_dir/events"
    export CADDY_TEST_READY_FILE="$test_tmp_dir/ready"
    export PATH="$SHELLSPEC_PROJECT_ROOT/spec/fixtures:$PATH"
    : >"$CADDY_TEST_EVENTS"
  }

  cleanup() {
    rm -rf "$test_tmp_dir"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'requires a readiness URL and backend command'
    When run script "$script"
    The status should equal 64
    The stderr should include 'usage:'
  End

  It 'does not start Caddy when the backend exits before readiness'
    export CADDY_TEST_BACKEND_MODE=exit_before_ready
    export CADDY_TEST_CURL_MODE=unavailable

    When run script "$script" 'http://127.0.0.1:3000/_up' -- fake-backend
    The status should equal 23
    The stdout should include 'Waiting for backend readiness'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_started'
    The contents of file "$CADDY_TEST_EVENTS" should not include 'caddy_started'
  End

  It 'waits for an exact HTTP 200 before starting Caddy'
    export CADDY_TEST_BACKEND_MODE=delayed_ready
    export CADDY_TEST_CURL_MODE=delayed_ready
    export CADDY_TEST_CADDY_MODE=exit

    When run script "$script" 'http://127.0.0.1:3000/_up' -- fake-backend
    The status should equal 29
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_checked_before_ready'
    The contents of file "$CADDY_TEST_EVENTS" should not include 'caddy_started_before_ready'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_started'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_term'
  End

  It 'rejects successful statuses other than HTTP 200'
    export CADDY_TEST_BACKEND_MODE=exit_before_ready
    export CADDY_TEST_CURL_MODE=no_content

    When run script "$script" 'http://127.0.0.1:3000/_up' -- fake-backend
    The status should equal 23
    The stdout should include 'Waiting for backend readiness'
    The contents of file "$CADDY_TEST_EVENTS" should not include 'caddy_started'
  End

  It 'terminates Caddy when the backend exits after readiness'
    export CADDY_TEST_BACKEND_MODE=exit_after_ready
    export CADDY_TEST_CURL_MODE=ready
    export CADDY_TEST_CADDY_MODE=wait

    When run script "$script" 'http://127.0.0.1:3000/_up' -- fake-backend
    The status should equal 23
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_started'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_term'
  End

  It 'terminates the backend when Caddy exits'
    export CADDY_TEST_BACKEND_MODE=wait
    export CADDY_TEST_CURL_MODE=ready
    export CADDY_TEST_CADDY_MODE=exit

    When run script "$script" 'http://127.0.0.1:3000/_up' -- fake-backend
    The status should equal 29
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_started'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_term'
  End

  It 'forwards SIGTERM and stops both children'
    export CADDY_TEST_BACKEND_MODE=wait
    export CADDY_TEST_CURL_MODE=ready
    export CADDY_TEST_CADDY_MODE=wait

    When run command ruby spec/fixtures/send_signal.rb "$script" TERM
    The status should equal 143
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_term'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_term'
  End

  It 'forwards SIGINT and stops both children'
    export CADDY_TEST_BACKEND_MODE=wait
    export CADDY_TEST_CURL_MODE=ready
    export CADDY_TEST_CADDY_MODE=wait

    When run command ruby spec/fixtures/send_signal.rb "$script" INT
    The status should equal 130
    The stdout should include 'Backend ready; starting Caddy'
    The contents of file "$CADDY_TEST_EVENTS" should include 'caddy_term'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_term'
  End

  It 'stops the backend and never starts Caddy after the fixed readiness deadline'
    export CADDY_TEST_BACKEND_MODE=wait
    export CADDY_TEST_CURL_MODE=unavailable

    When run script "$script" 'http://127.0.0.1:3000/_up' -- fake-backend
    The status should equal 124
    The stdout should include 'Waiting for backend readiness'
    The stderr should include 'Backend readiness timed out after 45 seconds'
    The contents of file "$CADDY_TEST_EVENTS" should include 'backend_term'
    The contents of file "$CADDY_TEST_EVENTS" should not include 'caddy_started'
  End
End
