require "test_helper"

# Most tests are in test/protocol. Tests here are outside of the protocol, but are necessary anyway.
module Charon
  class ProxyGrantingTicketTest < Test::Unit::TestCase
    context "A ProxyGrantingTicket" do
      setup do
        @redis = Redis.new
        @pgt = Charon::ProxyGrantingTicket.create!("http://example.com", @redis)
      end

      should "return a ticket" do
        assert_not_nil @pgt.ticket
      end
    end
  end
end
