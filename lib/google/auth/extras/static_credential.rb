# frozen_string_literal: true

module Google
  module Auth
    module Extras
      # This credential uses a static access token.
      class StaticCredential < Signet::OAuth2::Client
        class AuthorizationExpired < StandardError; end

        # A credential using a static access token.
        #
        # @param access_token [String]
        #   The access token to use.
        #
        def initialize(access_token:)
          super(
            access_token: access_token,
            expires_at: TokenInfo.lookup_access_token(access_token).fetch('exp'),
            issued_at: nil,
          )
        end

        def fetch_access_token(*)
          raise RefreshNotSupported
        rescue RefreshNotSupported
          # This is a simple trick for getting the cause to be set.
          raise Signet::AuthorizationError, 'Refresh not supported'
        end

        def inspect
          "#<#{self.class.name} @access_token=[REDACTED] @expires_at=#{expires_at.inspect}>"
        end
      end
    end
  end
end
