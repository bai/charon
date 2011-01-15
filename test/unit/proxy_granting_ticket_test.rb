require_relative "../test_helper"

# Most tests are in test/protocol. Tests here are outside of the protocol, but are necessary anyway.
class ProxyGrantingTicketTest < Test::Unit::TestCase
  context "A ProxyGrantingTicket" do
    setup do
      @redis = Redis.new
      @pgt = ProxyGrantingTicket.new("http://example.com")
      @pgt.save!(@redis)
    end

    should "return a ticket" do
      assert_not_nil @pgt.ticket
    end
  end
end
