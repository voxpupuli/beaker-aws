require 'rspec/core/rake_task'
require 'github_changelog_generator/task'

namespace :changelog do
  # Gets the github token needed for github_changelog_generator
  # - from env var CHANGELOG_GITHUB_TOKEN
  # - if unset, will be limited in number of queries allowed to github
  # - setup a token at https://github.com/settings/tokens
  def github_token
    ENV["CHANGELOG_GITHUB_TOKEN"]
  end

  GitHubChangelogGenerator::RakeTask.new :full do |config|
    config.token = github_token
    config.user = "puppetlabs"
    config.project = "beaker-aws"
    # Sets next version in the changelog
    # - if unset, newest changes will be listed as 'unreleased'
    # - setting this value directly sets section title on newest changes
    if !ENV['NEW_VERSION'].nil?
      config.future_release = ENV["NEW_VERSION"]
    end
  end

  GitHubChangelogGenerator::RakeTask.new :unreleased do |config|
    config.token = github_token
    config.user = "puppetlabs"
    config.project = "beaker-aws"
    config.unreleased_only = true
    config.output = "" # blank signals clg to print to output rather than a file
  end
end

namespace :test do

  namespace :spec do

    desc "Run spec tests"
    RSpec::Core::RakeTask.new(:run) do |t|
      t.rspec_opts = ['--color']
      t.pattern = 'spec/'
    end

    desc "Run spec tests with coverage"
    RSpec::Core::RakeTask.new(:coverage) do |t|
      ENV['BEAKER_TEMPLATE_COVERAGE'] = 'y'
      t.rspec_opts = ['--color']
      t.pattern = 'spec/'
    end

  end

  namespace :acceptance do

    desc <<-EOS
A quick acceptance test, named because it has no pre-suites to run
    EOS
    task :quick do

      # setup & load_path of beaker's acceptance base and lib directory
      beaker_gem_spec = Gem::Specification.find_by_name('beaker')
      beaker_gem_dir = beaker_gem_spec.gem_dir
      beaker_test_base_dir = File.join(beaker_gem_dir, 'acceptance/tests/base')
      load_path_option = File.join(beaker_gem_dir, 'acceptance/lib')

      sh("beaker",
         "--hosts", "acceptance/config/nodes/hosts.yml",
         "--tests", beaker_test_base_dir,
         "--log-level", "debug",
         "--load-path", load_path_option)
    end

  end

end

# namespace-named default tasks.
# these are the default tasks invoked when only the namespace is referenced.
# they're needed because `task :default` in those blocks doesn't work as expected.
task 'test:spec' => 'test:spec:run'
task 'test:acceptance' => 'test:acceptance:quick'

# global defaults
task :test => 'test:spec'
task :default => :test

###########################################################
#
#   Documentation Tasks
#
###########################################################
DOCS_DAEMON = "yard server --reload --daemon --server thin"
FOREGROUND_SERVER = 'bundle exec yard server --reload --verbose --server thin lib/beaker'

def running?( cmdline )
  ps = `ps -ef`
  found = ps.lines.grep( /#{Regexp.quote( cmdline )}/ )
  if found.length > 1
    raise StandardError, "Found multiple YARD Servers. Don't know what to do."
  end

  yes = found.empty? ? false : true
  return yes, found.first
end

def pid_from( output )
  output.squeeze(' ').strip.split(' ')[1]
end

desc 'Start the documentation server in the foreground'
task :docs => 'docs:clear' do
  original_dir = Dir.pwd
  Dir.chdir( File.expand_path(File.dirname(__FILE__)) )
  sh FOREGROUND_SERVER
  Dir.chdir( original_dir )
end

namespace :docs do

  desc 'Clear the generated documentation cache'
  task :clear do
    original_dir = Dir.pwd
    Dir.chdir( File.expand_path(File.dirname(__FILE__)) )
    sh 'rm -rf docs'
    Dir.chdir( original_dir )
  end

  desc 'Generate static documentation'
  task :gen => 'docs:clear' do
    original_dir = Dir.pwd
    Dir.chdir( File.expand_path(File.dirname(__FILE__)) )
    output = `bundle exec yard doc`
    puts output
    if output =~ /\[warn\]|\[error\]/
      fail "Errors/Warnings during yard documentation generation"
    end
    Dir.chdir( original_dir )
  end

  desc 'Run the documentation server in the background, alias `bg`'
  task :background => 'docs:clear' do
    yes, output = running?( DOCS_DAEMON )
    if yes
      puts "Not starting a new YARD Server..."
      puts "Found one running with pid #{pid_from( output )}."
    else
      original_dir = Dir.pwd
      Dir.chdir( File.expand_path(File.dirname(__FILE__)) )
      sh "bundle exec #{DOCS_DAEMON}"
      Dir.chdir( original_dir )
    end
  end

  task(:bg) { Rake::Task['docs:background'].invoke }

  desc 'Check the status of the documentation server'
  task :status do
    yes, output = running?( DOCS_DAEMON )
    if yes
      pid = pid_from( output )
      puts "Found a YARD Server running with pid #{pid}"
    else
      puts "Could not find a running YARD Server."
    end
  end

  desc "Stop a running YARD Server"
  task :stop do
    yes, output = running?( DOCS_DAEMON )
    if yes
      pid = pid_from( output )
      puts "Found a YARD Server running with pid #{pid}"
      `kill #{pid}`
      puts "Stopping..."
      yes, output = running?( DOCS_DAEMON )
      if yes
        `kill -9 #{pid}`
        yes, output = running?( DOCS_DAEMON )
        if yes
          puts "Could not Stop Server!"
        else
          puts "Server stopped."
        end
      else
        puts "Server stopped."
      end
    else
      puts "Could not find a running YARD Server"
    end
  end
end
