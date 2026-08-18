#!/usr/bin/env ruby

script, signal = ARGV
pid = Process.spawn(script, 'http://127.0.0.1:3000/_up', '--', 'fake-backend')
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5

loop do
  events = File.exist?(ENV.fetch('CADDY_TEST_EVENTS')) ? File.read(ENV.fetch('CADDY_TEST_EVENTS')) : ''
  break if events.lines.include?("caddy_started\n")

  if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
    Process.kill('TERM', pid)
    Process.wait(pid)
    warn 'Caddy did not start before the signal-test deadline'
    exit 1
  end

  sleep 0.05
end

Process.kill(signal, pid)
_, status = Process.wait2(pid)
exit(status.exitstatus || 128 + status.termsig)
