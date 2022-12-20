$: << File.expand_path("../../lib", __FILE__)
require 'bundler/setup'
require 'omniauth-spiffy-oauth2'

require 'minitest/autorun'
require 'fakeweb'
require 'json'
require 'active_support/core_ext/hash'

OmniAuth.config.logger = Logger.new(nil)

# Omniauth 2.0.0 deprecates the use of :get to mitigate the effects of CVE-2015-9284
# It's use within the app framework is not believed to cause an exposure as the use
# of Omniauth does not involve third-party accounts.
# The issue is fully discussed here - https://github.com/omniauth/omniauth/pull/809
# Shopify have indicated that it is not a problem - https://github.com/Shopify/omniauth-shopify-oauth2/issues/81
OmniAuth.config.allowed_request_methods = [:post, :get]

FakeWeb.allow_net_connect = false
