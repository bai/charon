require "addressable/uri"

require "helpers"
require "models/ticket"
require "models/login_ticket"
require "models/proxy_ticket"
require "models/service_ticket"
require "models/ticket_granting_ticket"
require "models/proxy_granting_ticket"
require "strategies/base"
require "strategies/simple"

module Sinatra
  module I18n
    module Helpers
      def t(*args)
        ::I18n::t(*args)
      end
    end

    def self.registered(app)
      app.helpers I18n::Helpers

      Dir["#{app.root}/locales/*.yml"].each do |f|
        ::I18n.backend.load_translations File.expand_path(f, app.root + "/locales")
      end
    end
  end
end

module Authentication
  class Server < Sinatra::Base
    include Authentication::Helpers

    set :redis, Proc.new { Redis.new }
    set :locales, %w(en ru)
    set :root, File.join(File.dirname(__FILE__), "/..")
    set :public, File.join(root, "/public")
    set :services, { "pipeline" => "http://pipeline.metaconomy.com" }
    set :error_codes, { 200 => "OK", 101 => "Invalid service", 102 => "Invalid request", 103 => "Invalid ticket" }

    register Sinatra::I18n

    use Rack::Session::Cookie
    use Warden::Manager do |manager|
      manager.failure_app = self
      manager.default_scope = :cas
      manager.scope_defaults(:cas, :strategies => [ :simple ], :action => "login")
    end

    before do
      I18n.locale = params[:l] || "en"
    end

    get "/serviceLogin" do
      @service = params[:s]
      @service_url = service_url(@service)
      @renew = [ true, "true", "1", 1 ].include?(params[:r])
      @gateway = [ true, "true", "1", 1 ].include?(params[:g])

      if @renew
        @login_ticket = LoginTicket.create!(settings.redis)
        erb(:login)
      elsif @gateway
        if @service_url
          if ticket_granting_ticket
            st = ServiceTicket.new(params[:s], ticket_granting_ticket.username)
            st.save!(settings.redis)
            redirect_url = @service_url.clone
            if @service_url.query_values.nil?
              redirect_url.query_values = @service_url.query_values = { :t => st.ticket }
            else
              redirect_url.query_values = @service_url.query_values.merge(:t => st.ticket)
            end
            redirect redirect_url.to_s, 303
          else
            redirect @service_url.to_s, 303
          end
        else
          @login_ticket = LoginTicket.create!(settings.redis)
          erb(:login)
        end
      else
        if ticket_granting_ticket
          if @service_url
            st = ServiceTicket.new(@service_url, ticket_granting_ticket.username)
            st.save!(settings.redis)
            redirect_url = @service_url.clone
            if @service_url.query_values.nil?
              redirect_url.query_values = @service_url.query_values = { :t => st.ticket }
            else
              redirect_url.query_values = @service_url.query_values.merge(:t => st.ticket)
            end
            redirect redirect_url.to_s, 303
          else
            erb(:logged_in)
          end
        else
          @login_ticket = LoginTicket.create!(settings.redis)
          erb(:login)
        end
      end
    end

    post "/serviceLogin" do
      username, password, service = params[:username], params[:password], params[:s]

      # Redirecting to credential requestor if we don't have these params
      redirect "/serviceLogin", 303 unless username && password && login_ticket
      # Failures will throw back to self, which we've registered with Warden to handle login failures
      warden.authenticate!(:scope => :cas, :action => "unauthenticated")

      tgt = TicketGrantingTicket.new(username)
      tgt.save!(settings.redis)
      cookie = tgt.to_cookie(request.host)
      response.set_cookie(*cookie)

      if service_url(service) && !warn
        st = ServiceTicket.new(service_url(service), username)
        st.save!(settings.redis)
        redirect service_url(service) + "?t=#{st.ticket}", 303
      else
        erb(:logged_in)
      end
    end

    get %r{(proxy|service)Validate} do
      service, ticket = params[:s], params[:t]

      result = if service_url(service) && ticket
        if service_ticket
          if service_ticket.valid_for_service?(service_url(service))
            [ 200, { "username" => service_ticket.username } ]
          else
            [ 101 ]
          end
        else
          [ 103 ]
        end
      else
        [ 102 ]
      end

      resp(*result)
    end

    get "/serviceLogout" do
      url = params[:url]

      if ticket_granting_ticket
        @ticket_granting_ticket.destroy!(settings.redis)
        response.delete_cookie(*ticket_granting_ticket.to_cookie(request.host))
        warden.logout(:cas)
      end
      @login_ticket = LoginTicket.create!(settings.redis)
      erb(:login)
    end

    post "/unauthenticated" do
      @login_ticket = LoginTicket.create!(settings.redis)
      erb(:login)
    end

    private
      def warden
        request.env["warden"]
      end

      def ticket_granting_ticket
        @ticket_granting_ticket ||= TicketGrantingTicket.validate(request.cookies["tgt"], settings.redis)
      end

      def login_ticket
        @login_ticket ||= LoginTicket.validate!(params[:lt], settings.redis)
      end

      def service_ticket
        @service_ticket ||= ServiceTicket.find!(params[:ticket], settings.redis)
      end

      def service_url(service)
        Addressable::URI.parse(settings.services[service] + "/auth/remote/callback")
      end

      def resp(status, data = nil)
        content_type :json
        { :status => status, :data => data }.to_json
      end
  end
end
