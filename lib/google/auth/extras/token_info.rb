# frozen_string_literal: true

module Google
  module Auth
    module Extras
      # This module provides methods to lookup details about authenication tokens,
      # primarily for their expiration.
      module TokenInfo
        extend self

        class LookupFailed < StandardError; end
        class LookupMalformed < LookupFailed; end

        TOKEN_INFO_URI = 'https://oauth2.googleapis.com/tokeninfo'
        private_constant :TOKEN_INFO_URI

        # Lookup the details for a valid access token, including it's expiration.
        #
        # @raise [LookupFailed]
        #   If the token is invalid (including expired).
        #
        # @return [Hash]
        #
        # @see https://cloud.google.com/docs/authentication/token-types#access-contents
        #
        def lookup_access_token(token)
          lookup(access_token: token)
        end

        private

        def lookup(query)
          url = Addressable::URI.parse(TOKEN_INFO_URI)
          url.query_values = query

          response = Faraday.default_connection.get(url.normalize.to_s)

          raise LookupFailed, response.body.to_s unless response.status == 200

          credentials = Signet::OAuth2.parse_credentials(response.body, response.headers['Content-Type'])

          raise LookupMalformed, 'Missing token expiry' unless credentials['exp']

          credentials['exp'] = parse_as_integer(credentials['exp'])
          credentials['expires_in'] = parse_as_integer(credentials['expires_in'])

          credentials.transform_values(&:freeze).freeze
        end

        def parse_as_integer(str)
          return nil if str.nil?

          str.to_i.tap do |value|
            raise LookupMalformed unless value.to_s == str
          end
        end
      end
    end
  end
end
