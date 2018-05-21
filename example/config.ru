require 'bundler/setup'
require 'sinatra/base'
require 'omniauth-spiffy-stores-oauth2'

SCOPE = 'read_products,read_orders,read_customers,write_shipping'
SPIFFY_STORES_API_KEY = ENV['SPIFFY_STORES_API_KEY']
SPIFFY_STORES_SHARED_SECRET = ENV['SPIFFY_STORES_SHARED_SECRET']

unless SPIFFY_STORES_API_KEY && SPIFFY_STORES_SHARED_SECRET
  abort("SPIFFY_STORES_API_KEY and SPIFFY_STORES_SHARED_SECRET environment variables must be set")
end

class App < Sinatra::Base
  get '/' do
    <<-HTML
    <html>
    <head>
      <title>Spiffy Stores Oauth2</title>
    </head>
    <body>
      <form action="/auth/spiffy_stores" method="get">
      <label for="shop">Enter your store's URL:</label>
      <input type="text" name="shop" placeholder="your-shop-name.spiffystores.com">
      <button type="submit">Log In</button>
      </form>
    </body>
    </html>
    HTML
  end

  get '/auth/:provider/callback' do
    <<-HTML
    <html>
    <head>
      <title>Spiffy Stores Oauth2</title>
    </head>
    <body>
      <h3>Authorized</h3>
      <p>Shop: #{request.env['omniauth.auth'].uid}</p>
      <p>Token: #{request.env['omniauth.auth']['credentials']['token']}</p>
    </body>
    </html>
    HTML
  end

  get '/auth/failure' do
    <<-HTML
    <html>
    <head>
      <title>Spiffy Stores Oauth2</title>
    </head>
    <body>
      <h3>Failed Authorization</h3>
      <p>Message: #{params[:message]}</p>
    </body>
    </html>
    HTML
  end
end

use Rack::Session::Cookie, secret: SecureRandom.hex(64)

use OmniAuth::Builder do
  provider :spiffy_stores, SPIFFY_STORES_API_KEY, SPIFFY_STORES_SHARED_SECRET, :scope => SCOPE
end

run App.new
