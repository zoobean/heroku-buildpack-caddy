class App
  def call(env)
    case env['PATH_INFO']
    when '/'
      [200, {'Content-Type' => 'text/html'}, ['<h1>Hello from Ruby/Rack!</h1><p>This is a test app for Caddy buildpack.</p>']]
    when '/health'
      [200, {'Content-Type' => 'application/json'}, ['{"status":"ok","message":"healthy"}']]
    when '/api/test'
      [200, {'Content-Type' => 'application/json'}, ['{"data":"test response","timestamp":"' + Time.now.to_s + '"}']]
    else
      [404, {'Content-Type' => 'text/html'}, ['<h1>404 Not Found</h1>']]
    end
  end
end