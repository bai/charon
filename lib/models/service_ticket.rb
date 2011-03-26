class ServiceTicket < Ticket
  class << self
    def find!(ticket, store)
      username = store.hget(ticket, :username)
      service = store.hget(ticket, :service)

      if service && username
        store.del ticket
        new(service, username)
      end
    end

    def create!(service, username, store)
      st = self.new(service, username)
      st.save!(store)
      st
    end

    def expire_time
      300
    end
  end

  attr_reader :username, :service

  def initialize(service, username)
    @service = service
    @username = username
  end

  def valid_for_service?(s)
    service == s
  end

  def ticket
    @ticket ||= "ST-#{random_string(117)}".to_s
  end

  def remaining_time(store)
    store.ttl ticket
  end

  def save!(store)
    store.pipelined do
      store.hset ticket, :service, self.service
      store.hset ticket, :username, self.username
      store.expire ticket, self.class.expire_time
    end
  end
end
