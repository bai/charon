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
    set :services, { "pipeline" => "http://127.0.0.1:3000", "account" => "http://127.0.0.1:3000" }
    set :error_codes, { "OK" => 200, "INVALID_SERVICE" => 101, "INVALID_REQUEST" => 102, "INVALID_TICKET" => 103 }

    register Sinatra::I18n

    use Rack::Session::Cookie
    use Warden::Manager do |manager|
      manager.failure_app = self
      manager.default_scope = :remote
      manager.scope_defaults(:remote, :strategies => [ :simple ], :action => "login")
    end

    before do
      I18n.locale = params[:l] || "en"
    end

    get "/serviceLogin" do
      @service = params[:service]
      @service_url = service_url(@service)
      @renew = [ true, "true", "1", 1 ].include?(params[:renew])
      @gateway = [ true, "true", "1", 1 ].include?(params[:gateway])

      if @renew
        @login_ticket = LoginTicket.create!(settings.redis)
        erb(:login)
      elsif @gateway
        if @service_url
          if ticket_granting_ticket
            st = ServiceTicket.new(@service, ticket_granting_ticket.username)
            st.save!(settings.redis)
            redirect_url = @service_url.clone
            if @service_url.query_values.nil?
              redirect_url.query_values = @service_url.query_values = { :ticket => st.ticket }
            else
              redirect_url.query_values = @service_url.query_values.merge(:ticket => st.ticket)
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
            st = ServiceTicket.new(@service, ticket_granting_ticket.username)
            st.save!(settings.redis)
            redirect_url = @service_url.clone
            if @service_url.query_values.nil?
              redirect_url.query_values = @service_url.query_values = { :ticket => st.ticket }
            else
              redirect_url.query_values = @service_url.query_values.merge(:ticket => st.ticket)
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
      username = params[:username]
      password = params[:password]
      service  = params[:service]

      # Redirecting to credential requestor if we don't have these params
      # redirect "/serviceLogin" + "?service=account", 303 unless username && password && service && login_ticket
      # Failures will throw back to self, which we've registered with Warden to handle login failures
      warden.authenticate!(:scope => :remote, :action => "unauthenticated")

      tgt = TicketGrantingTicket.new(username)
      tgt.save!(settings.redis)
      cookie = tgt.to_cookie(request.host)
      response.set_cookie(*cookie)

      if service_url(service)
        st = ServiceTicket.new(service, username)
        st.save!(settings.redis)
        redirect service_url(service).to_s + "?ticket=#{st.ticket}", 303
      else
        erb(:logged_in)
      end
    end

    get %r{(proxy|service)Validate} do
      service, ticket = params[:service], params[:ticket]

      result = if service_url(service) && ticket
        if service_ticket
          if service_ticket.valid_for_service?(service)
            [ settings.error_codes["OK"], { "username" => service_ticket.username } ]
          else
            [ settings.error_codes["INVALID_SERVICE"] ]
          end
        else
          [ settings.error_codes["INVALID_TICKET"] ]
        end
      else
        [ settings.error_codes["INVALID_REQUEST"] ]
      end

      resp(*result)
    end

    get "/serviceLogout" do
      url = params[:url]

      if ticket_granting_ticket
        @ticket_granting_ticket.destroy!(settings.redis)
        response.delete_cookie(*ticket_granting_ticket.to_cookie(request.host))
        warden.logout(:remote)
      end
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
        Addressable::URI.parse(settings.services[service || "account"] + "/auth/remote/callback")
      end

      def resp(status, data = nil)
        content_type :json
        Yajl::Encoder.encode(:status => status, :data => data)
      end
  end
end
