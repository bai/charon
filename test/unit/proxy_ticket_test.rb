require "test_helper"

# Most tests are in test/protocol. Tests here are outside of the protocol, but are necessary anyway.
module Charon
  class ProxyTicketTest < Test::Unit::TestCase
    context "A ProxyTicket" do
      setup do
        @redis = Redis.new
        @pt = Charon::ProxyTicket.new("http://example.com")
        @pt.save!(@redis)
      end

      should "be able to retrieve remaining time" do
        assert_equal(300, @pt.remaining_time(@redis))
      end

      should "return a ticket" do
        assert_not_nil @pt.ticket
      end
    end
  end
end
