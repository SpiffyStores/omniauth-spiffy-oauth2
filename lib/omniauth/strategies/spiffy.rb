# frozen_string_literal: true

require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class Spiffy < OmniAuth::Strategies::OAuth2
      # Available scopes: content themes products customers orders script_tags shipping
      # read_*  or write_*
      DEFAULT_SCOPE = 'read_products'
      SCOPE_DELIMITER = ','
      MINUTE = 60
      CODE_EXPIRES_AFTER = 10 * MINUTE

      option :client_options, {
        :authorize_url => '/admin/oauth/authorize',
        :token_url => '/admin/oauth/token'
      }

      option :callback_url
      option :spiffy_stores_domain, 'spiffystores.com'
      option :old_client_secret

      # When `true`, the user's permission level will apply (in addition to
      # the requested access scope) when making API requests to Spiffy Stores.
      option :per_user_permissions, false

      # When `true`, the user's authorization phase will fail if the granted scopes
      # mismatch the requested scopes.
      option :validate_granted_scopes, true

      option :setup, proc {|env|
        strategy = env['omniauth.strategy']

        spiffy_auth_params = strategy.session['spiffy.omniauth_params'] ||
          strategy.session['omniauth.params'] ||
          strategy.request.params

        spiffy_auth_params = spiffy_auth_params && spiffy_auth_params.with_indifferent_access
        store = if spiffy_auth_params && spiffy_auth_params['store']
          "https://#{spiffy_auth_params['store']}"
        else
          ''
        end

        strategy.options[:client_options][:site] = store
      }

      uid { URI.parse(options[:client_options][:site]).host }

      extra do
        if access_token
          {
            'associated_user' => access_token['associated_user'],
            'associated_user_scope' => access_token['associated_user_scope'],
            'scope' => access_token['scope'],
            'session' => access_token['session']
          }
        end
      end

      def valid_site?
        !!(/\A(https|http)\:\/\/[a-zA-Z0-9][a-zA-Z0-9\-]*\.#{Regexp.quote(options[:spiffy_stores_domain])}[\/]?\z/ =~ options[:client_options][:site])
      end

      def valid_signature?
        return false unless request.POST.empty?

        params = request.GET
        signature = params['hmac']
        timestamp = params['timestamp']
        return false unless signature && timestamp

        return false unless timestamp.to_i > Time.now.to_i - CODE_EXPIRES_AFTER

        new_secret = options.client_secret
        old_secret = options.old_client_secret

        validate_signature(new_secret) || (old_secret && validate_signature(old_secret))
      end

      def valid_scope?(token)
        params = options.authorize_params.merge(options_for("authorize"))
        return false unless token && params[:scope] && token['scope']
        expected_scope = normalized_scopes(params[:scope]).sort
        (expected_scope == token['scope'].split(SCOPE_DELIMITER).sort)
      end

      def normalized_scopes(scopes)
        scope_list = scopes.to_s.split(SCOPE_DELIMITER).map(&:strip).reject(&:empty?).uniq
        ignore_scopes = scope_list.map { |scope| scope =~ /\A(unauthenticated_)?write_(.*)\z/ && "#{$1}read_#{$2}" }.compact
        scope_list - ignore_scopes
      end

      def self.encoded_params_for_signature(params)
        params = params.dup
        params.delete('hmac')
        params.delete('signature') # deprecated signature
        Rack::Utils.build_query(params.sort)
      end

      def self.hmac_sign(encoded_params, secret)
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, secret, encoded_params)
      end

      def valid_permissions?(token)
        return false unless token

        return true if options[:per_user_permissions] && token['associated_user']
        return true if !options[:per_user_permissions] && !token['associated_user']

        false
      end

      def fix_https
        options[:client_options][:site] = options[:client_options][:site].gsub(/\Ahttp\:/, 'https:')
      end

      def setup_phase
        super
        fix_https
      end

      def request_phase
        if valid_site?
          super
        else
          fail!(:invalid_site)
        end
      end

      def callback_phase
        return fail!(:invalid_site, CallbackError.new(:invalid_site, "OAuth endpoint is not a Spiffy Stores site.")) unless valid_site?
        return fail!(:invalid_signature, CallbackError.new(:invalid_signature, "Signature does not match, it may have been tampered with.")) unless valid_signature?

        token = build_access_token
        unless valid_scope?(token)
          return fail!(:invalid_scope, CallbackError.new(:invalid_scope, "Scope does not match, it may have been tampered with."))
        end
        unless valid_permissions?(token)
          return fail!(:invalid_permissions, CallbackError.new(:invalid_permissions, "Requested API access mode does not match."))
        end

        super
      rescue ::OAuth2::Error => e
        fail!(:invalid_credentials, e)
      end

      def build_access_token
        @built_access_token ||= super
      end

      def authorize_params
        super.tap do |params|
          params[:scope] = normalized_scopes(params[:scope] || DEFAULT_SCOPE).join(SCOPE_DELIMITER)
          params[:grant_options] = ['per-user'] if options[:per_user_permissions]
        end
      end

      def callback_url
        options[:callback_url] || full_host + script_name + callback_path
      end

      private

      def validate_signature(secret)
        params = request.GET
        calculated_signature = self.class.hmac_sign(self.class.encoded_params_for_signature(params), secret)
        Rack::Utils.secure_compare(calculated_signature, params['hmac'])
      end
    end
  end
end
