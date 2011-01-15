class TicketGrantingTicket < Ticket
  class << self
    def validate(ticket, store)
      if ticket && username = store[ticket]
        new(username, ticket)
      end
    end
  end

  attr_reader :username

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
  end

  def to_cookie(domain, path = "/")
    [ "tgt", { :value => ticket, :path => path } ]
  end
end
