require "test_helper"

# Most tests are in test/protocol. Tests here are outside of the protocol, but are necessary anyway.
module Charon
  class ServiceTicketTest < Test::Unit::TestCase
    context "A TicketGrantingTicket" do
      setup do
        @redis = Redis.new
        assert_not_nil @redis
        @st = Charon::ServiceTicket.create!("http://localhost", "quentin", @redis)
      end

      context "find!" do
        should "be able to retrieve the username" do
          assert_equal("quentin", @st.username)
          assert_equal("http://localhost", @st.service)

          st2 = Charon::ServiceTicket.find!(@st.ticket, @redis)
          assert_equal("quentin", st2.username)
          assert_equal("http://localhost", st2.service)
        end

        should "only be retrievable once" do
          st2 = Charon::ServiceTicket.find!(@st.ticket, @redis)
          assert_nil Charon::ServiceTicket.find!(@st.ticket, @redis)
        end
      end

      context "valid for service?" do
        setup do
          @retrieved_ticket = Charon::ServiceTicket.find!(@st.ticket, @redis)
        end
        should "be true if url passed in is the same as in the the store" do
          assert @retrieved_ticket.valid_for_service?("http://localhost")
        end

        should "be false if url passed in is not the same as in the store" do
          assert_false @retrieved_ticket.valid_for_service?("http://wronghost")
        end
      end
    end
  end
end
