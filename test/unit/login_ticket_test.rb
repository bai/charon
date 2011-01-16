require "test_helper"

# Most tests are in test/protocol. Tests here are outside of the protocol, but are necessary anyway.
class LoginTicketTest < Test::Unit::TestCase
  context "A LoginTicket" do
    setup do
      @redis = Redis.new
      @lt = LoginTicket.new
      @lt.save!(@redis)
    end

    should "be able to retrieve remaining time" do
      assert_equal(300, @lt.remaining_time(@redis))
    end

    should "return a ticket" do
      assert_not_nil @lt.ticket
    end
  end
end
