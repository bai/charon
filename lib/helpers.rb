module Authentication
  module Helpers
    private
      def random_string(max_length = 29)
        rg =  Crypt::ISAAC.new
        max = 4294619050
        r = "#{Time.now.to_i}r%X%X%X%X%X%X%X%X" %
          [ rg.rand(max), rg.rand(max), rg.rand(max), rg.rand(max),
           rg.rand(max), rg.rand(max), rg.rand(max), rg.rand(max) ]
        r[0..max_length-1]
      end
  end
end
