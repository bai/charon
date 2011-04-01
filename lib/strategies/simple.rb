module Charon
  module Strategies
    class Simple < Base
      User = Struct.new(:username, :password)

      def authenticate!
        if params["username"] == "test" && params["password"] == "password"
          u = User.new(params["username"], params["password"])
          success!(u)
        else
          fail!
        end
      end
    end
  end
end

Warden::Strategies.add(:simple, Charon::Strategies::Simple)
