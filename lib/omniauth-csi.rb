require "omniauth-csi/version"
require 'omniauth/strategies/csi'

module Omniauth
  module CSI
    OmniAuth.config.add_camelization 'csi', 'CSI'
  end
end
