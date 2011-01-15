class ProxyGrantingTicket < Ticket
  class << self
    def validate!(ticket, store)
      if service_name = store[ticket]
        new(service_name)
      end
    end
  end

  def initialize(service_name)
    @service_name = service_name
  end

  def valid_for_service?(url)
    @service_name == url
  end

  def ticket
    @ticket ||= "PGT-#{random_string}".to_s
  end

  def save!(store)
    store[ticket] = @service_name
  end

  def create_proxy_ticket!(store)
    pt = ProxyTicket.new(@service_name, self)
    pt.save!(store)
    pt
  end
end
