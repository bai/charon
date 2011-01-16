require "rake/testtask"

Rake::TestTask.new do |t|
  t.libs << "test"
  t.test_files = Dir["test/**/*_test.rb"].sort
  t.warning = true
  t.verbose = true
end
