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
    set :warden_strategies, [ :simple ]

    register Sinatra::I18n

    use Rack::Session::Cookie
    use Rack::Flash, :accessorize => [ :notice, :error ]
    use Warden::Manager do |manager|
      manager.failure_app = self
      manager.default_scope = :cas

      manager.scope_defaults(:cas,
        :strategies => settings.warden_strategies,
        :action => "login"
      )
    end

    configure :development do
      set :dump_errors
    end

    before do
      I18n.locale = determine_locale
    end

    get "/serviceLogin" do
      @service_url = Addressable::URI.parse(params[:service])
      @renew = [ true, "true", "1", 1 ].include?(params[:renew])
      @gateway = [ true, "true", "1", 1 ].include?(params[:gateway])

      if @renew
        @login_ticket = LoginTicket.create!(settings.redis)
        render_login
      elsif @gateway
        if @service_url
          if sso_session
            st = ServiceTicket.new(params[:service], sso_session.username)
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
          render_login
        end
      else
        if sso_session
          if @service_url
            st = ServiceTicket.new(params[:service], sso_session.username)
            st.save!(settings.redis)
            redirect_url = @service_url.clone
            if @service_url.query_values.nil?
              redirect_url.query_values = @service_url.query_values = { :ticket => st.ticket }
            else
              redirect_url.query_values = @service_url.query_values.merge(:ticket => st.ticket)
            end
            redirect redirect_url.to_s, 303
          else
            render_logged_in
          end
        else
          @login_ticket = LoginTicket.create!(settings.redis)
          render_login
        end
      end
    end

    post "/serviceLogin" do
      username = params[:username]
      password = params[:password]

      service_url = params[:service]

      warn = [ true, "true", "1", 1 ].include? params[:warn]
      # Spec is undefined about what to do without these params, so redirecting to credential requestor
      redirect "/serviceLogin", 303 unless username && password && login_ticket
      # Failures will throw back to self, which we've registered with Warden to handle login failures
      warden.authenticate!(:scope => :cas, :action => "unauthenticated")

      tgt = TicketGrantingTicket.new(username)
      tgt.save!(settings.redis)
      cookie = tgt.to_cookie(request.host)
      response.set_cookie(*cookie)

      if service_url && !warn
        st = ServiceTicket.new(service_url, username)
        st.save!(settings.redis)
        redirect service_url + "?ticket=#{st.ticket}", 303
      else
        render_logged_in
      end
    end

    get %r{(proxy|service)Validate} do
      service_url = params[:service]
      ticket = params[:ticket]
      # proxy_gateway = params[:pgtUrl]
      # renew = params[:renew]

      xml = if service_url && ticket
        if service_ticket
          if service_ticket.valid_for_service?(service_url)
            render_validation_success service_ticket.username
          else
            render_validation_error(:invalid_service)
          end
        else
          render_validation_error(:invalid_ticket, "ticket #{ticket} not recognized")
        end
      else
        render_validation_error(:invalid_request)
      end

      content_type :xml
      xml
    end

    # TODO: Think about more sane single sign-out solution than @logout = true.
    get "/serviceLogout" do
      url = params[:url]

      if sso_session
        @sso_session.destroy!(settings.redis)
        response.delete_cookie(*sso_session.to_cookie(request.host))
        warden.logout(:cas)
        flash.now[:notice] = t("logout_successful")
        if url
          msg = "  The application you just logged out of has provided a link it would like you to follow."
          msg += "Please <a href=\"#{url}\">click here</a> to access <a href=\"#{url}\">#{url}</a>"
          flash.now[:notice] += msg
        end
      end
      @login_ticket = LoginTicket.create!(settings.redis)
      render_login
    end

    post "/unauthenticated" do
      @login_ticket = LoginTicket.create!(settings.redis)
      flash[:error] = t("login_failed")
      render_login
    end

    def render_login
      erb :login
    end

    def render_logged_in
      erb :logged_in
    end

    # Override to add user info back to client applications
    def append_user_info(xml)
    end

    private
      def warden
        request.env["warden"]
      end

      def sso_session
        @sso_session ||= TicketGrantingTicket.validate(request.cookies["tgt"], settings.redis)
      end

      def ticket_granting_ticket
        @ticket_granting_ticket ||= sso_session
      end

      def login_ticket
        @login_ticket ||= LoginTicket.validate!(params[:lt], settings.redis)
      end

      def service_ticket
        @service_ticket ||= ServiceTicket.find!(params[:ticket], settings.redis)
      end

      def render_validation_error(code, message = nil)
        Nokogiri::XML::Builder.new do |xml|
          xml.serviceResponse("xmlns:cas" => "http://www.yale.edu/tp/cas") {
            xml.parent.namespace = xml.parent.namespace_definitions.first
            xml["cas"].authenticationFailure(message, :code => code.to_s.upcase)
          }
        end.to_xml
      end

      def render_validation_success(username)
        Nokogiri::XML::Builder.new do |xml|
          xml.serviceResponse("xmlns:cas" => "http://www.yale.edu/tp/cas") {
            xml.parent.namespace = xml.parent.namespace_definitions.first
            xml["cas"].authenticationSuccess {
              xml["cas"].user username
              append_user_info(xml)
            }
          }
        end.to_xml
      end

      def determine_locale
        language = case
          when params[:l] && !params[:l].empty?
            params[:l]
          when request.env["HTTP_ACCEPT_LANGUAGE"] && !request.env["HTTP_ACCEPT_LANGUAGE"].empty?
            request.env["HTTP_ACCEPT_LANGUAGE"]
          when request.env["HTTP_USER_AGENT"] && !request.env["HTTP_USER_AGENT"].empty? && request.env["HTTP_USER_AGENT"] =~ /[^a-z]([a-z]{2}(-[a-z]{2})?)[^a-z]/i
            $~[1]
          else
            "en"
        end.gsub("_", "-")

        # TODO: Need to confirm that this method of splitting the accepted language string is correct.
        if language =~ /[,;\|]/
          languages = language.split(/[,;\|]/)
        else
          languages = [ language ]
        end

        # Try to pick a locale exactly matching the desired identifier, otherwise fall back to locale without region
        # (i.e. given "en-US; de-DE", we would first look for "en-US", then "en", then "de-DE", then "de").
        #
        # TODO: This method of selecting the desired language might not be standards-compliant. For example,
        # http://www.w3.org/TR/ltli/ suggests that de-de and de-*-DE might be acceptable identifiers for selecting
        # various wildcards. The algorithm below does not currently support anything like this.
        settings.locales.find { |a| a =~ Regexp.new("\\A#{languages.join('|')}\\Z", "i") || a =~ Regexp.new("#{languages.join('|')}-\w*", "i") } || "en"
      end
  end
end
