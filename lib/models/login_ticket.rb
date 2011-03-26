class LoginTicket < Ticket
  class << self
    def validate!(ticket, store)
      if store.exists ticket
        store.del ticket
        new
      end
    end

    def create!(store)
      lt = self.new
      lt.save!(store)
      lt
    end

    def expire_time
      300
    end
  end

  def ticket
    @ticket ||= "LT-#{random_string}".to_s
  end

  def remaining_time(store)
    store.ttl ticket
  end

  def save!(store)
    store[ticket] = 1
    store.expire ticket, self.class.expire_time
  end
end
