require_relative "../test_helper"

# Most tests are in test/protocol. Tests here are outside of the protocol, but are necessary anyway.
class TicketGrantingTicketTest < Test::Unit::TestCase
  context "A TicketGrantingTicket" do
    setup do
      @redis = Redis.new
      @tgt = TicketGrantingTicket.new("quentin")
      @tgt.save!(@redis)
    end

    should "be able to retrieve the username" do
      assert_equal("quentin", @tgt.username)

      tgt2 = TicketGrantingTicket.validate(@tgt.ticket, @redis)
      assert_equal("quentin", @tgt.username)
    end

    should "return a ticket" do
      assert_not_nil @tgt.ticket
    end

    should "be able to destroy itself" do
      assert_not_nil TicketGrantingTicket.validate(@tgt.ticket, @redis)
      @tgt.destroy!(@redis)
      assert_nil TicketGrantingTicket.validate(@tgt.ticket, @redis)
    end
  end
end
