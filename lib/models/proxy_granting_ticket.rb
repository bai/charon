class ProxyGrantingTicket < Ticket
  class << self
    def validate!(ticket, store)
      if service_name = store[ticket]
        new(service_name)
      end
    end

    def create!(service_name, store)
      pgt = self.new(service_name)
      pgt.save!(store)
      pgt
    end
  end

  def initialize(service_name)
    @service_name = service_name
  end

  def valid_for_service?(service_name)
    @service_name == service_name
  end

  def ticket
    @ticket ||= "PGT-#{random_string(117)}".to_s
  end

  def save!(store)
    store[ticket] = @service_name
  end

  def create_proxy_ticket!(store)
    ProxyTicket.new(@service_name, store) # TODO: pass self?
  end
end
