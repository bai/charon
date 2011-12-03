module Charon
  class TicketGrantingTicket < Ticket
    class << self
      attr_accessor :expire_time

      def validate(ticket, store)
        if ticket && username = store[ticket]
          new(username, ticket)
        end
      end

      def create!(user, store)
        tgt = self.new(user)
        tgt.save!(store)
        tgt
      end
    end

    attr_reader :username

    self.expire_time = 300

    def initialize(user, ticket = nil)
      @username = user
      @ticket = ticket
    end

    def ticket
      @ticket ||= "TGC-#{random_string}".to_s
    end

    def destroy!(store)
      store.del self.ticket
    end

    def save!(store)
      store[ticket] = username
      store.expire ticket, self.class.expire_time
    end

    def to_cookie(domain, path = "/")
      [ "tgt", { :value => ticket, :path => path } ]
    end
  end
end
