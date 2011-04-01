module Charon
  class ProxyTicket < Ticket
    class << self
      def validate!(ticket, store)
        if service = store[ticket]
          store.del ticket
          new(service)
        end
      end

      def create!(service, store)
        pt = self.new(service)
        pt.save!(store)
        pt
      end

      def expire_time
        300
      end
    end

    def initialize(service)
      @service = service
    end

    def valid_for_service?(service)
      @service == service
    end

    def ticket
      @ticket ||= "PT-#{random_string(117)}".to_s
    end

    def remaining_time(store)
      store.ttl ticket
    end

    def save!(store)
      store[ticket] = @service
      store.expire ticket, self.class.expire_time
    end
  end
end
