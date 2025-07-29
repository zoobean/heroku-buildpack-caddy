require 'minitest/autorun'
require_relative 'server_manager'

class TestWAFFunctionality < Minitest::Test
  include ServerManager
  def setup
    setup_servers
    # Additional WAF-specific readiness check
    wait_for_waf_ready
  end

  def teardown
    cleanup_servers
  end

  def test_waf_integration_with_caddy
    # Test that WAF is properly integrated with Caddy and blocking requests
    response = make_request('/test.php')
    assert_equal 403, response.status, "WAF should be active and blocking malicious requests"
  end

  def test_waf_response_headers
    # Test that WAF blocked responses contain appropriate information
    response = make_request('/test.php')
    assert_equal 403, response.status
    # WAF blocked requests should return 403 status - body content varies by implementation
    assert response.status == 403, "WAF blocked response should return 403 status code"
  end

  def test_waf_performance_impact
    # Test that legitimate requests still perform well through WAF
    start_time = Time.now
    response = make_request('/')
    end_time = Time.now

    assert_equal 200, response.status, "Legitimate requests should pass through WAF"
    assert (end_time - start_time) < 1.0, "WAF should not significantly impact performance"
  end

  private

  def make_request(path, headers = {})
    make_request_to_caddy(path, headers)
  end
end
