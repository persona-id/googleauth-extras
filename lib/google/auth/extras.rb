# frozen_string_literal: true

require 'date'
require 'google/apis/iamcredentials_v1'
require 'signet/oauth_2/client'

require 'google/auth/extras/impersonated_credential'
require 'google/auth/extras/static_credential'
require 'google/auth/extras/token_info'
require 'google/auth/extras/version'

module Google
  module Auth
    # This module provides some extra features not supported in the normal googleauth gem.
    module Extras
      extend self

      # Raised when a credential does not support refresh, like a static
      # credential.
      class RefreshNotSupported < StandardError; end

      # A credential that impersonates a service account.
      #
      # @param base_credentials [Hash, String, Signet::OAuth2::Client]
      #   Credentials to use to impersonate the provided email address.
      #
      # @param delegate_email_addresses [String, Array<String>]
      #   The list of email address if there are intermediate service accounts that
      #   need to be impersonated using delegation.
      #
      # @param email_address [String]
      #   Email of the service account to impersonate.
      #
      # @param lifetime [String]
      #   The desired lifetime (in seconds) of the token before needing to be refreshed.
      #   Defaults to 1h, adjust as needed given a refresh is automatically performed
      #   when the token less than 60s of remaining life and refresh requires an
      #   additional API call.
      #
      # @param scope [String, Array<String>]
      #   The OAuth 2 scopes to request. Can either be formatted as a comma seperated string or array.
      #
      # @return [Google::Auth::Extras::ImpersonatedCredential]
      #
      # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
      # @see https://cloud.google.com/iam/docs/create-short-lived-credentials-delegated#sa-credentials-permissions
      #
      def impersonated_credential(email_address:, scope:, base_credentials: nil, delegate_email_addresses: nil, lifetime: nil)
        ImpersonatedCredential.new(
          base_credentials: base_credentials,
          delegate_email_addresses: delegate_email_addresses,
          email_address: email_address,
          lifetime: lifetime,
          scope: scope,
        )
      end

      # A credential using a static access token token.
      #
      # @param token [String]
      #   The access token to use.
      #
      # @return [Google::Auth::Extras::StaticCredential]
      #
      def static_credential(token)
        StaticCredential.new(access_token: token)
      end
    end
  end
end
