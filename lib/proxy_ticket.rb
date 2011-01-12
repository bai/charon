class ProxyTicket
  class << self
    def validate!(ticket, store)
      if service_url = store[ticket]
        store.del ticket
        new(service_url)
      end
    end

    def expire_time
      300
    end
  end

  def initialize(service_url)
    @service_url = service_url
  end

  def valid_for_service?(url)
    @service_url == url
  end

  def ticket
    @ticket ||= "PT-#{rand(100000000000000000)}".to_s
  end

  def remaining_time(store)
    store.ttl ticket
  end

  def save!(store)
    store[ticket] = @service_url
    store.expire ticket, self.class.expire_time
  end
end