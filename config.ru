require "rubygems"
require "bundler"
Bundler.require

$:.unshift File.join(File.dirname(__FILE__), "lib")
require "authentication"

run Authentication::Server
