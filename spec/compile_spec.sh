Describe 'bin/compile'
  script='bin/compile'

  setup() {
    test_tmp_dir="$(mktemp -d)"
    build_dir="$test_tmp_dir/build"
    cache_dir="$test_tmp_dir/cache"
    env_dir="$test_tmp_dir/env"
    mkdir -p "$build_dir" "$cache_dir" "$env_dir"
    printf 'v-test\n' >"$env_dir/CADDY_VERSION"

    export CADDY_TEST_BINARY="$SHELLSPEC_PROJECT_ROOT/spec/fixtures/compile/caddy"
    export CADDY_TEST_EVENTS="$test_tmp_dir/events"
    export PATH="$SHELLSPEC_PROJECT_ROOT/spec/fixtures/compile:$PATH"
    : >"$CADDY_TEST_EVENTS"
  }

  cleanup() {
    rm -rf "$test_tmp_dir"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'validates a Rails app Caddyfile during the build'
    mkdir -p "$build_dir/config"
    printf 'require-env WAF_ADMIN_PASS_HASH\n' >"$build_dir/config/Caddyfile"
    printf 'test-hash\n' >"$env_dir/WAF_ADMIN_PASS_HASH"
    : >"$build_dir/Gemfile"

    When run script "$script" "$build_dir" "$cache_dir" "$env_dir"
    The status should equal 0
    The stdout should include 'Caddyfile is valid'
    The contents of file "$CADDY_TEST_EVENTS" should include 'validate --config config/Caddyfile --adapter caddyfile'
    The contents of file "$CADDY_TEST_EVENTS" should include 'required environment present'
  End

  It 'fails the build when the app Caddyfile is invalid'
    printf 'invalid\n' >"$build_dir/Caddyfile"

    When run script "$script" "$build_dir" "$cache_dir" "$env_dir"
    The status should equal 1
    The stdout should include 'Validating Caddyfile'
    The stderr should include 'invalid Caddyfile'
    The stderr should include 'ERROR: Caddyfile validation failed: Caddyfile'
  End

  It 'does not require a Caddyfile when none of the supported locations exists'
    : >"$build_dir/Gemfile"

    When run script "$script" "$build_dir" "$cache_dir" "$env_dir"
    The status should equal 0
    The stdout should include 'No Caddyfile found'
    The contents of file "$CADDY_TEST_EVENTS" should not include 'validate'
  End
End
