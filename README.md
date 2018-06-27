[![Build Status](https://api.travis-ci.com/SpiffyStores/omniauth-spiffy-oauth2.png?branch=master)](https://travis-ci.com/SpiffyStores/omniauth-spiffy-oauth2)

# OmniAuth Spiffy Stores

Spiffy Stores OAuth2 Strategy for OmniAuth 1.0.

## Installing

Add to your `Gemfile`:

```ruby
gem 'omniauth-spiffy-oauth2'
```

Then `bundle install`.

## Usage

`OmniAuth::Strategies::Spiffy` is simply a Rack middleware. Read [the OmniAuth 1.0 docs](https://github.com/intridea/omniauth) for detailed instructions.

Here's a quick example, adding the middleware to a Rails app in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :spiffy, ENV['SPIFFY_STORES_API_KEY'], ENV['SPIFFY_STORES_SHARED_SECRET']
end
```

Authenticate the user by having them visit /auth/spiffy with a `store` query parameter of their store's spiffystores.com domain. For example, the following form could be used

```html
<form action="/auth/spiffy" method="get">
  <label for="shop">Enter your store's URL:</label>
  <input type="text" name="shop" placeholder="your-store-url.spiffystores.com">
  <button type="submit">Log In</button>
</form>
```

## Configuring

You can configure the scope, which you pass in to the `provider` method via a `Hash`:

* `scope`: A comma-separated list of permissions you want to request from the user. See [the SpiffyStores API docs](https://www.spiffystores.com.au/kb/tutorials_oauth) for a full list of available permissions.

For example, to request `read_products`, `read_orders` and `write_content` permissions and display the authentication page:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :spiffy, ENV['SPIFFY_STORES_API_KEY'], ENV['SPIFFY_STORES_SHARED_SECRET'], :scope => 'read_products,read_orders,write_content'
end
```

## Authentication Hash

Here's an example *Authentication Hash* available in `request.env['omniauth.auth']`:

```ruby
{
  :provider => 'spiffy',
  :uid => 'example.spiffystores.com',
  :credentials => {
    :token => 'afasd923kjh0934kf', # OAuth 2.0 access_token, which you store and use to authenticate API requests
  }
}
```

## License

Copyright (c) 2018 by Spiffy Stores

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
