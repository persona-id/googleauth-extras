# frozen_string_literal: true

module Google
  module Auth
    module Extras
      # This credential impersonates a service account.
      class ImpersonatedCredential < Signet::OAuth2::Client
        class MissingScope < StandardError; end

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
        # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
        # @see https://cloud.google.com/iam/docs/create-short-lived-credentials-delegated#sa-credentials-permissions
        #
        def initialize(email_address:, scope:, base_credentials: nil, delegate_email_addresses: nil, lifetime: nil)
          super(scope: scope)

          raise MissingScope if self.scope.nil? || self.scope.empty?

          @iam_credentials_service = Google::Apis::IamcredentialsV1::IAMCredentialsService.new.tap do |ics|
            ics.authorization = base_credentials if base_credentials
          end

          @impersonate_delegates = Array(delegate_email_addresses).map do |email|
            transform_email_to_name(email)
          end

          @impersonate_lifetime = lifetime

          @impersonate_name = transform_email_to_name(email_address)
        end

        def fetch_access_token(*)
          access_token_request = Google::Apis::IamcredentialsV1::GenerateAccessTokenRequest.new(
            scope: scope,
          )

          # The Google SDK doesn't like nil repeated values, but be careful with others as well.
          access_token_request.delegates = @impersonate_delegates unless @impersonate_delegates.empty?
          access_token_request.lifetime = @impersonate_lifetime unless @impersonate_lifetime.nil?

          access_token_response = @iam_credentials_service.generate_service_account_access_token(@impersonate_name, access_token_request)

          {
            access_token: access_token_response.access_token,
            expires_at: DateTime.rfc3339(access_token_response.expire_time).to_time,
          }
        end

        def inspect
          "#<#{self.class.name}" \
            " @access_token=#{@access_token ? '[REDACTED]' : 'nil'}" \
            " @expires_at=#{expires_at.inspect}" \
            " @impersonate_delegates=#{@impersonate_delegates.inspect}" \
            " @impersonate_lifetime=#{@impersonate_lifetime.inspect}" \
            " @impersonate_name=#{@impersonate_name.inspect}" \
            '>'
        end

        private

        def transform_email_to_name(email)
          "projects/-/serviceAccounts/#{email}"
        end
      end
    end
  end
end
