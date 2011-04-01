require "rubygems"
require "bundler"
Bundler.require

$:.unshift File.join(File.dirname(__FILE__), "lib")
require "charon"

run Charon::Server
