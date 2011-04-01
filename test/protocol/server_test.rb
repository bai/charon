require "test_helper"

class Charon::ServerTest < Test::Unit::TestCase
  module Rack
    module Test
      DEFAULT_HOST = "localhost"
    end
  end

  def app
    app ||= Charon::Server
  end

  def sso_session_for(username)
    @tgt = Charon::TicketGrantingTicket.create!("quentin", @redis)
    cookie = @tgt.to_cookie("localhost", "/")

    # Rack's set_cookie appears to be worse than useless, unless I'm mistaken
    @cookie = "#{cookie[0]}=#{cookie[1][:value]}"
    @tgt
  end

  def assert_invalid_request_json_response(last_response)
    assert_equal("application/json", last_response.content_type)
    json = Yajl::Parser.parse(last_response.body)

    assert_equal(102, json["status"])
  end

  def assert_authentication_success_json_response(last_response)
    assert_equal("application/json", last_response.content_type)
    json = Yajl::Parser.parse(last_response.body)

    assert_equal("quentin", json["data"]["name"])
  end

  def assert_invalid_ticket_json_response(last_response)
    assert_equal("application/json", last_response.content_type)
    json = Yajl::Parser.parse(last_response.body)

    assert_equal(103, json["status"])
  end

  def assert_authenticate_failure_json_response(last_response)
    assert_equal("application/json", last_response.content_type)
    json = Yajl::Parser.parse(last_response.body)

    assert json["status"] < 200, "Expected authentication failure status code in #{json}"
  end

  def assert_invalid_service_json_response(last_response)
    assert_equal("application/json", last_response.content_type)
    json = Yajl::Parser.parse(last_response.body)

    assert_equal(101, json["status"])
  end

  context "An authentication server" do
    setup do
      @test_service = "account"
      @redis = Redis.new
      @parser = URI::Parser.new
    end

    context "/serviceLogin as credential requestor" do
      context "parameters" do
        should "request credentials" do
          get "/serviceLogin"

          assert_have_selector "form"
        end

        # context "a single sign-on session already exists" do
        #   setup { sso_session_for("quentin") }
        #
        #   should "notify the client that it is already logged in" do
        #     get "/serviceLogin", {}, "HTTP_COOKIE" => @cookie
        #
        #     assert_match(/already logged in/, last_response.body)
        #   end
        # end

        context "with a 'service' parameter" do
          context "a single sign-on session already exists" do
            setup { sso_session_for("quentin") }

            should "generate a service ticket and redirect to the service" do
              get "/serviceLogin", { :service => @test_service }, "HTTP_COOKIE" => @cookie

              assert last_response.redirect?
              assert_equal("/auth/charon/callback", Addressable::URI.parse(last_response.headers["Location"]).path)
            end

            should "persist the ticket for retrieval later" do
              get "/serviceLogin", { :service => @test_service }, "HTTP_COOKIE" => @cookie
              ticket_number = last_response.inspect[/ST-[A-Za-z0-9]+/]
              st = Charon::ServiceTicket.find!(ticket_number, @redis)
              assert_not_nil st
              assert st.valid_for_service?(@test_service)
            end
          end

          # Not specified, but good sanity check
          context "an invalid single sign-on session exists" do
            should "not generate a service ticket and rediect" do
              get "/serviceLogin", { :service => @test_service }, "HTTP_COOKIE" => "tgt=TGC-1234567"

              assert !last_response.headers["Location"]
            end
          end
        end

        context "with a 'renew' parameter" do
          setup { @params = { :renew => true } }

          context "a single sign-on session already exists" do
            setup { sso_session_for("quentin") }

            should "bypass single sign on and force the client to renew" do
              get "/serviceLogin", @params, "HTTP_COOKIE" => @cookie
              body = last_response.body
              assert_have_selector "input[name='username']"
              assert_have_selector "input[name='password']"
              assert_have_selector "input[name='lt']"
            end
          end

          context "with a 'gateway' parameter" do
            # RECOMMENDED
            should "have 'renew' take precedence over a 'gateway' parameter"
          end
        end

        context "with a 'gateway' parameter" do
          setup { @params = { :gateway => true } }

          context "with a 'service' parameter" do
            setup { @params[:service] = @test_service }

            must "not ask for credentials" do
              get "/serviceLogin", @params

              assert_have_no_selector "input[name='username']"
              assert_have_no_selector "input[name='password']"
              assert_have_no_selector "input[name='lt']"
            end

            must "redirect the client to the service URL without a ticket" do
              get "/serviceLogin", @params

              assert_equal("http://127.0.0.1:3000/auth/charon/callback", last_response.headers["Location"])
            end

            context "a single sign-on session already exists" do
              setup { sso_session_for("quentin") }

              may "redirect the client to the service URL, appending a valid service ticket" do
                get "/serviceLogin", @params, "HTTP_COOKIE" => @cookie

                assert last_response.redirect?
                assert_equal("/auth/charon/callback", Addressable::URI.parse(last_response.headers["Location"]).path)
              end

              should "persist the ticket for retrieval later" do
                get "/serviceLogin", @params, "HTTP_COOKIE" => @cookie
                ticket_number = last_response.inspect[/ST-[A-Za-z0-9]+/]
                st = Charon::ServiceTicket.find!(ticket_number, @redis)
                assert_not_nil st
                assert st.valid_for_service?(@test_service)
              end

              may "interpose an advisory page informing the client that an authentication has taken place"
            end
          end
        end
      end

      context "response for username/password authentication" do
        must "include a form with the parameters, 'username', 'password', and 'lt'" do
          get "/serviceLogin"

          assert_have_selector "input[name='username']"
          assert_have_selector "input[name='password']"
          assert_have_selector "input[name='lt']"
          assert_match("LT-", last_response.body)
        end

        context "with a 'service' parameter" do
          must "include the parameter 'service' in the form" do
            get "/serviceLogin?service=#{@test_service}"

            assert_have_selector "input[name='service']"
            assert field_named("service").value == @test_service
          end
        end

        context "the form" do
          must "be submitted through the HTTP POST method" do
            get "/serviceLogin"
            assert_match(/method="post"/, last_response.body)
          end

          must "be submitted to /serviceLogin" do
            get "/serviceLogin"
            assert_match(/action="\/serviceLogin"/, last_response.body)
          end
        end
      end

      context "response for trust authentication" do
        # TODO
      end

      context "response for single sign-on authentication" do
        context "a single sign-on session already exists" do
          # I think this was already covered
          context "with a 'renew' parameter" do
          end
        end
      end
    end

    context "/serviceLogin as credential acceptor" do
      setup do
        @lt = Charon::LoginTicket.create!(@redis)
      end

      context "parameters common to all types of authentication" do
        context "with a 'service' parameter" do
          must "redirect the client to the 'service' url"
        end
      end

      context "parameters for username/password authentication" do
        must "require 'username', 'password', and 'lt' (login ticket) parameters" do
          post "/serviceLogin"
          assert !last_response.ok?

          post "/serviceLogin", { :username => "test", :password => "password", :lt => "LT-FAKE" }
          assert !last_response.ok?

          post "/serviceLogin", { :username => "test", :password => "password", :lt => @lt.ticket }
          assert last_response.redirect?

          post "/serviceLogin", { :username => "test", :password => "password", :lt => @lt.ticket }
          assert !last_response.ok?
        end
      end

      context "parameters for trust verification" do
        # TODO
      end

      context "response" do
        context "successful login:" do
          setup { @params = { :username => "test", :password => "password", :lt => @lt.ticket } }

          should "set a ticket-granting cookie" do
            post "/serviceLogin", @params
            assert_match(/tgt=TGC-/, last_response.headers.to_s)
          end

          context "with a 'service' parameter" do
            setup do
              @service_param_url = /auth\/charon\/callback/ # FIXME: regex is not obvious
              @params[:service] = @test_service
            end

            must "redirect the client to the URL specified by the 'service' parameter" do
              post "/serviceLogin", @params
              assert last_response.redirect?
              assert_match @service_param_url, last_response.headers["Location"]
            end

            must "not forward the client's credentials to the 'service'" do
              post "/serviceLogin", @params
              assert_no_match(/testpassword/, last_response.inspect)
              assert_no_match(/quentin/, last_response.inspect)
            end

            must "cause the client to send a GET request to the 'service'" do
              post "/serviceLogin", @params
              assert_equal 303, last_response.status
            end

            must "include a valid service ticket, passed as the HTTP request parameter, 'ticket' with request" do
              post "/serviceLogin", @params
              assert_match(/ticket/, last_response.inspect)
              assert_match(/ST-[0-9]+/, last_response.inspect)
            end

            should "persist the ticket for retrieval later" do
              post "/serviceLogin", @params
              ticket_number = last_response.inspect[/ST-[A-Za-z0-9]+/]
              st = Charon::ServiceTicket.find!(ticket_number, @redis)
              assert_not_nil st
              assert st.valid_for_service?(@params[:service])
            end
          end
        end

        context "with failure" do
          setup do
            @params = { :username => "test", :password => "badpassword", :lt => @lt.ticket, :service => 'account' }
            post "/serviceLogin", @params
          end

          should "redirect to /unauthorized but render /serviceLogin" do
            assert last_response.redirect?
            follow_redirect!

            assert_have_selector "input[name='username']"
            assert_have_selector "input[name='password']"
            assert_have_selector "input[name='lt']"
          end

          should "preserve the service url in a hidden field" do
            assert last_response.redirect?
            follow_redirect!
            assert_have_selector "input[name='service']", :value => 'account'
          end

          should "provide an opportunity to attempt to login again"
        end
      end
    end

    context "/serviceLogout" do
      setup { sso_session_for("quentin") }

      should "destroy the ticket granting ticket" do
        assert_not_nil Charon::TicketGrantingTicket.validate(@tgt.ticket, @redis)
        get "/serviceLogout", "","HTTP_COOKIE" => @cookie
        assert_nil Charon::TicketGrantingTicket.validate(@tgt.ticket, @redis)
      end

      should "show login page" do
        get "/serviceLogout", "","HTTP_COOKIE" => @cookie
        assert_have_selector "input[name='username']"
        assert_have_selector "input[name='password']"
      end

      context "optional url parameter" do
        setup do
          get "/serviceLogout", { :url => "http://myreturn.app" }, "HTTP_COOKIE" => @cookie
        end

        should "reditect a user to the provided URL"
      end

      context "response" do
        must "display a page stating that user has been logged out"

        context "with a 'url' parameter" do
          may "link back to 'url' on the logout page"
        end
      end
    end

    context "/serviceValidate" do
      setup do
        @st = Charon::ServiceTicket.create!(@test_service, "quentin", @redis)
      end

      must "issue proxy granting tickets when requested."

      context "if it receives a proxy ticket" do
        must "not return a successful validation if it receives a proxy ticket"

        should "have ane error message that explains in the json that validation failed because a proxy ticket was passed"
      end

      context "parameters" do
        must "require 'service' and 'ticket' parameters" do
          get "/serviceValidate"
          assert_invalid_request_json_response(last_response)

          get "/serviceValidate", { :service => @test_service }
          assert_invalid_request_json_response(last_response)

          get "/serviceValidate", { :ticket => 'ticket' }
          assert_invalid_ticket_json_response(last_response)
        end

        context "with 'service' and 'ticket' parameters" do
          context "with a 'pgtUrl' parameter" do
            must "perform proxy callback"
          end

          context "with a 'renew' parameter" do
            must "fail ticket validation if the service ticket was issued from a single sign-on session"
          end
        end
      end

      context "response" do
        context "ticket validation success" do
          should "produce an JSON service response" do
            get "/serviceValidate", { :service => @test_service, :ticket => @st.ticket }

            assert_authentication_success_json_response(last_response)
          end
        end

        context "ticket validation failure" do
          should "produce an JSON service response" do
            get "/serviceValidate", { :service => @test_service, :ticket => "ST-FAKE" }

            assert_authenticate_failure_json_response(last_response)
          end
        end
      end

      context "error codes" do
        context "not all of the required request parameters present" do
          should "respond with INVALID_REQUEST" do
            get "/serviceValidate"

            assert_invalid_request_json_response(last_response)
          end
        end

        context "ticket provided was not valid or the ticket did not come from an intial login and 'renew' was set" do
          should "respond with INVALID_TICKET" do
            get "/serviceValidate", :service => @test_service, :ticket => "ST-FAKE"
            assert_invalid_ticket_json_response(last_response)
          end
        end

        context "the ticket provided was valid, but the service specified did not match the service associated with the ticket" do
          setup { get "/serviceValidate", :service => "pipeline", :ticket => @st.ticket }

          should "respond with INVALID_SERVICE" do
            assert_invalid_service_json_response(last_response)
          end

          must "invalidate the ticket" do
            assert !Charon::ServiceTicket.find!(@st.ticket, @redis)
          end
        end

        context "an internal error occurred during ticket validation" do
          should "respond with INTERNAL_ERROR" # Not sure how to test this
        end
      end

      context "proxy callback" do
        # TODO
      end

      context "/proxyValidate" do
        context "performing the same validation tasks as /serviceValidate" do
          setup do
            @st = Charon::ServiceTicket.create!(@test_service, "quentin", @redis)
          end

          context "parameters" do
            must "require 'service' and 'ticket' parameters" do
              get "/proxyValidate"
              assert_invalid_request_json_response(last_response)

              get "/proxyValidate", { :service => @test_service }
              assert_invalid_request_json_response(last_response)

              get "/proxyValidate", { :ticket => "ticket" }
              assert_invalid_ticket_json_response(last_response)
            end

            context "with 'service' and 'ticket' parameters" do
              context "with a 'pgtUrl' parameter" do
                must "perform proxy callback"
              end

              context "with a 'renew' parameter" do
                must "fail ticket validation if the service ticket was issued from a single sign-on session"
              end
            end
          end

          context "response" do
            context "ticket validation success" do
              should "produce an JSON service response" do
                get "/proxyValidate", { :service => @test_service, :ticket => @st.ticket }
                assert_authentication_success_json_response(last_response)
              end
            end

            context "ticket validation failure" do
              should "produce an JSON service response" do
                get "/proxyValidate", { :service => @test_service, :ticket => "ST-FAKE" }
                assert_authenticate_failure_json_response(last_response)
              end
            end
          end
        end

        context "error codes" do
          context "not all of the required request parameters present" do
            should "respond with INVALID_REQUEST" do
              get "/proxyValidate"
              assert_invalid_request_json_response(last_response)
            end
          end

          context "ticket provided was not valid or the ticket did not come from an intial login and 'renew' was set" do
            should "respond with INVALID_TICKET" do
              get "/proxyValidate", :service => @test_service, :ticket => "ST-FAKE"
              assert_invalid_ticket_json_response(last_response)
            end
          end

          context "the ticket provided was valid, but the service specified did not match the service associated with the ticket" do
            setup { get "/proxyValidate", :service => "pipeline", :ticket => @st.ticket }

            should "respond with INVALID_SERVICE" do
              assert_invalid_service_json_response(last_response)
            end

            must "invalidate the ticket" do
              assert !Charon::ServiceTicket.find!(@st.ticket, @redis)
            end
          end

          context "an internal error occurred during ticket validation" do
            should "respond with INTERNAL_ERROR" # Not sure how to test this
          end
        end

        must "validate proxy tickets"

        must "be capable of validating both service tickets and proxy tickets."
      end
    end

    context "service ticket" do
      setup do
        @st = Charon::ServiceTicket.create!(@test_service, "quentin", @redis)
      end

      context "properties" do
        should "be valid only for the service that was specified to /serviceLogin when they were generated" do
          assert @st.valid_for_service?(@test_service)
          assert !@st.valid_for_service?("http://google.com")
        end

        should "not include the service identifier in the service ticket" do
          assert !@st.ticket.include?(@test_service)
        end

        must "be valid for only one attempt" do
          assert Charon::ServiceTicket.find!(@st.ticket, @redis)

          assert !Charon::ServiceTicket.find!(@st.ticket, @redis)
        end

        should "expire unvalidated service tickets in a reasonable period of time (recommended to be less than 5 minutes)" do
          assert @st.remaining_time(@redis) <= 300
        end

        must "contain adequate secure random data so that a ticket is not guessable" # Is this even testable?

        must "begin with the characters 'ST-'" do
          assert_match(/^ST-/, @st.ticket)
        end

        must "be at least 32 characters in length" do
          assert @st.ticket.gsub(/^ST-/, "").length >= 32 # Services must accept a minimum of 32 chars. Recommended 256.
        end
      end
    end

    context "proxy ticket" do
      setup do
        @pt = Charon::ProxyTicket.create!(@test_service, @redis)
      end

      context "properties" do
        should "be valid only for the service that was specified to /proxy when they were generated" do
          assert @pt.valid_for_service?(@test_service)
          assert !@pt.valid_for_service?("http://google.com")
        end

        should "not include the service identifier in the proxy ticket" do
          assert !@pt.ticket.include?(@test_service)
        end

        must "be valid for only one attempt" do
          assert Charon::ProxyTicket.validate!(@pt.ticket, @redis)

          assert !Charon::ProxyTicket.validate!(@pt.ticket, @redis)
        end

        should "expire unvalidated service tickets in a reasonable period of time (recommended to be less than 5 minutes)" do
          assert @pt.remaining_time(@redis) <= 300
        end

        must "contain adequate secure random data so that a ticket is not guessable" # Is this even testable?

        should "begin with the characters 'PT-'" do
          assert_match(/^PT-/, @pt.ticket)
        end

        must "begin with the characters 'ST-' or 'PT-'" do
          assert_match(/^(ST|PT)-/, @pt.ticket)
        end

        must "be at least 32 characters in length" do
          assert @pt.ticket.gsub(/^(ST|PT)-/, "").length >= 32 # Services must accept a minimum of 32 chars. Recommended 256.
        end
      end
    end

    context "proxy-granting ticket" do
      setup do
        @pgt = Charon::ProxyGrantingTicket.create!(@test_service, @redis)
      end

      context "properties" do
        may "be able to be used by services to obtain multiple proxy tickets"

        must "expire with the client logs out of the system"

        must "contain adequate secure random data so that the ticket-granting cookie is not guessable in a reasonable period of time"

        must "begin with the characters 'PGT-'"

        must "be at least 64 characters in length" do
          assert @pgt.ticket.gsub(/^PGT-/, "").length >= 64 # Services must accept a minimum of 64 chars. Recommended 256.
        end
      end
    end

    context "login ticket" do
      setup do
        @lt = Charon::LoginTicket.create!(@redis)
      end

      context "properties" do
        must "be probablistically unique"

        must "be valid for only one attempt" do
          assert Charon::LoginTicket.validate!(@lt.ticket, @redis)
          assert !Charon::LoginTicket.validate!(@lt.ticket, @redis)
        end

        should "begin with the characters 'LT-'" do
          assert_match(/^LT-/, @lt.ticket)
        end
      end
    end

    context "ticket-granting cookie" do
      setup do
        @tgt = Charon::TicketGrantingTicket.create!("quentin", @redis)
      end

      context "properties" do
        must "be set to expire at the end of the client's browser session" do
          cookie_args = @tgt.to_cookie("http://localhost", "/cas")
          assert_equal(nil, cookie_args[1][:expires])
        end

        must "have a cookie path set to be as restrictive as possible" do
          cookie_args = @tgt.to_cookie("http://localhost", "/cas")
          assert_equal("/cas", cookie_args[1][:path])
        end

        must "contain adequate secure random data so that the ticket-granting cookie is not guessable in a reasonable period of time"

        should "begin with the characters 'TGC-'" do
          assert_match(/^TGC-/, @tgt.ticket)
        end
      end
    end

    context "ticket and ticket-granting cookie character set" do
      setup do
        @tickets = [
          Charon::LoginTicket.new,
          Charon::ServiceTicket.new("account", "foo"),
          Charon::TicketGrantingTicket.new("foo")
        ]
      end

      must "contain only characters from the set {A-Z, a-z, 0-9, and the hyphen character}" do
        @tickets.each do |t|
          assert_match(/^[A-Za-z0-9\-]+$/, t.ticket)
        end
      end
    end
  end
end
