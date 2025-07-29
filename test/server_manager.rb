require 'socket'
require 'httpx'
require 'webrick'

module ServerManager
  def self.find_available_port
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    server.close
    port
  end

  def setup_servers
    @ruby_port = ServerManager.find_available_port
    @caddy_port = ServerManager.find_available_port
    @ruby_server_ready = false
    @caddy_server_ready = false
    @shutdown_requested = false

    # Start Ruby/Rack app on available port
    start_ruby_server
    
    # Wait for Ruby server to be ready before starting Caddy
    wait_for_ruby_server
    
    # Start Caddy proxy server
    start_caddy_server
    
    # Wait for Caddy server to be ready
    wait_for_caddy_server
  end

  def start_ruby_server
    require_relative 'app'

    @ruby_server_thread = Thread.new do
      begin
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
        @ruby_server_ready = true
        @ruby_server.start
      rescue => e
        puts "Ruby server failed to start: #{e.message}" unless @shutdown_requested
      end
    end
  end

  def start_caddy_server
    @caddy_thread = Thread.new do
      begin
        # Set environment variables for Caddyfile
        ENV['PORT'] = @caddy_port.to_s
        ENV['RUBY_PORT'] = @ruby_port.to_s
        @caddy_server_ready = true
        system("../dist/caddy-darwin-arm64 run --config Caddyfile --adapter caddyfile")
      rescue => e
        puts "Caddy server failed to start: #{e.message}" unless @shutdown_requested
      end
    end
  end

  def wait_for_ruby_server
    timeout = 30
    start_time = Time.now
    
    while !@ruby_server_ready && (Time.now - start_time) < timeout
      Thread.pass
    end
    
    # Additional check to ensure server is actually responding
    (timeout * 10).times do
      break if @shutdown_requested
      begin
        response = HTTPX.get("http://localhost:#{@ruby_port}/health")
        return true if response.status == 200
      rescue
        # Server not ready yet, continue waiting
      end
      sleep 0.1
    end
    
    raise "Ruby server failed to start within timeout" unless @shutdown_requested
  end

  def wait_for_caddy_server
    timeout = 30
    start_time = Time.now
    
    while !@caddy_server_ready && (Time.now - start_time) < timeout
      Thread.pass
    end
    
    # Additional check to ensure Caddy is actually responding
    (timeout * 10).times do
      break if @shutdown_requested
      begin
        # Check if Caddy server is responding (might be blocked by WAF, so check for any response)
        response = HTTPX.get("http://localhost:#{@caddy_port}/health")
        return true if [200, 403].include?(response.status)
      rescue
        # Server not ready yet, continue waiting
      end
      sleep 0.1
    end
    
    raise "Caddy server failed to start within timeout" unless @shutdown_requested
  end

  def wait_for_waf_ready
    timeout = 30
    start_time = Time.now
    
    while !@caddy_server_ready && (Time.now - start_time) < timeout
      Thread.pass
    end
    
    # Additional check to ensure Caddy with WAF is actually responding
    (timeout * 10).times do
      break if @shutdown_requested
      begin
        # Test a request that should be blocked to confirm WAF is active
        response = make_request_to_caddy('/test.php')
        return true if response.status == 403  # WAF is working
      rescue
        # Server not ready yet, continue waiting
      end
      sleep 0.1
    end
    
    raise "Caddy server with WAF failed to start within timeout" unless @shutdown_requested
  end

  def cleanup_servers
    @shutdown_requested = true
    
    # Gracefully shutdown Ruby server
    if @ruby_server
      @ruby_server.shutdown
    end
    
    # Kill Caddy process
    system("pkill -f 'caddy.*run.*Caddyfile' > /dev/null 2>&1")
    
    # Wait for processes to terminate gracefully
    threads_to_join = [@ruby_server_thread, @caddy_thread].compact
    threads_to_join.each do |thread|
      begin
        thread.join(2.0)  # Wait up to 2 seconds for graceful shutdown
      rescue
        # If graceful shutdown fails, force kill
        thread.kill if thread.alive?
      end
    end
    
    # Final cleanup
    @ruby_server = nil
    @ruby_server_thread = nil
    @caddy_thread = nil
  end

  def make_request_to_caddy(path, headers = {}, params = {})
    url = "http://localhost:#{@caddy_port}#{path}"
    if params.empty?
      HTTPX.get(url, headers: headers)
    else
      HTTPX.get(url, headers: headers, params: params)
    end
  end
end