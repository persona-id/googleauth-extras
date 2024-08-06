# frozen_string_literal: true

module Google
  module Auth
    module Extras
      # This credential impersonates a service account.
      class ImpersonatedCredential < Signet::OAuth2::Client
        include IdentityCredentialRefreshPatch

        attr_reader :quota_project_id

        # A credential that impersonates a service account.
        #
        # The `email_address` of the service account to impersonate may be the exact
        # same as the one represented in `base_credentials` for any desired situation
        # but a handy usage is for going from and access token to an ID token (aka
        # using `target_audience`).
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
        # @param include_email [Boolean]
        #   Include the service account email in the token. If set to true, the token will
        #   contain email and email_verified claims.
        #   Only supported when using a target_audience.
        #
        # @param lifetime [String]
        #   The desired lifetime (in seconds) of the token before needing to be refreshed.
        #   Defaults to 1h, adjust as needed given a refresh is automatically performed
        #   when the token less than 60s of remaining life and refresh requires an
        #   additional API call.
        #   Only supported when not using a target_audience.
        #
        # @param quota_project_id [String]
        #   The project ID used for quota and billing. This project may be different from
        #   the project used to create the credentials.
        #
        # @param scope [String, Array<String>]
        #   The OAuth 2 scopes to request. Can either be formatted as a comma seperated string or array.
        #   Only supported when not using a target_audience.
        #
        # @param target_audience [String]
        #   The audience for the token, such as the API or account that this token grants access to.
        #
        # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
        # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateIdToken
        # @see https://cloud.google.com/iam/docs/create-short-lived-credentials-delegated#sa-credentials-permissions
        # @see https://developers.google.com/identity/protocols/oauth2/scopes
        #
        def initialize(
          email_address:,
          base_credentials: nil,
          delegate_email_addresses: nil,
          include_email: nil,
          lifetime: nil,
          quota_project_id: nil,
          scope: nil,
          target_audience: nil
        )
          super(client_id: target_audience, scope: scope, target_audience: target_audience)

          if self.target_audience.nil? || self.target_audience.empty?
            raise(ArgumentError, 'Must provide scope or target_audience') if self.scope.nil? || self.scope.empty?
          elsif self.scope.nil? || self.scope.empty?
            # no-op
          else
            raise ArgumentError, 'Must provide scope or target_audience, not both'
          end

          @iam_credentials_service = Google::Apis::IamcredentialsV1::IAMCredentialsService.new.tap do |ics|
            ics.authorization = base_credentials if base_credentials
          end

          @impersonate_delegates = Array(delegate_email_addresses).map do |email|
            transform_email_to_name(email)
          end

          # This is true when target_audience is passed
          if token_type == :id_token
            @impersonate_include_email = include_email
          elsif !include_email.nil?
            raise ArgumentError, 'Can only provide include_email when using target_audience'
          end

          # This is true when scope is passed
          if token_type == :access_token
            @impersonate_lifetime = lifetime
          elsif !lifetime.nil?
            raise ArgumentError, 'Cannot provide lifetime when using target_audience'
          end

          @impersonate_name = transform_email_to_name(email_address)

          @quota_project_id = quota_project_id
        end

        def fetch_access_token(*)
          token_request = if token_type == :id_token
                            Google::Apis::IamcredentialsV1::GenerateIdTokenRequest.new(
                              audience: target_audience,
                            )
                          else
                            Google::Apis::IamcredentialsV1::GenerateAccessTokenRequest.new(
                              scope: scope,
                            )
                          end

          # The Google SDK doesn't like nil repeated values, but be careful with others as well.
          token_request.delegates = @impersonate_delegates unless @impersonate_delegates.empty?
          if token_type == :id_token
            token_request.include_email = @impersonate_include_email unless @impersonate_include_email.nil?
          else
            token_request.lifetime = @impersonate_lifetime unless @impersonate_lifetime.nil?
          end

          if token_type == :id_token
            id_token_response = @iam_credentials_service.generate_service_account_id_token(@impersonate_name, token_request)

            {
              id_token: id_token_response.token,
            }
          else
            access_token_response = @iam_credentials_service.generate_service_account_access_token(@impersonate_name, token_request)

            {
              access_token: access_token_response.access_token,
              expires_at: DateTime.rfc3339(access_token_response.expire_time).to_time,
            }
          end
        end

        def inspect
          if token_type == :id_token
            "#<#{self.class.name}" \
              " @expires_at=#{expires_at.inspect}" \
              " @id_token=#{@id_token ? '[REDACTED]' : 'nil'}" \
              " @impersonate_delegates=#{@impersonate_delegates.inspect}" \
              " @impersonate_include_email=#{@impersonate_include_email.inspect}" \
              " @impersonate_name=#{@impersonate_name.inspect}" \
              " @quota_project_id=#{@quota_project_id.inspect}" \
              " @target_audience=#{@target_audience.inspect}" \
              '>'
          else
            "#<#{self.class.name}" \
              " @access_token=#{@access_token ? '[REDACTED]' : 'nil'}" \
              " @expires_at=#{expires_at.inspect}" \
              " @impersonate_delegates=#{@impersonate_delegates.inspect}" \
              " @impersonate_lifetime=#{@impersonate_lifetime.inspect}" \
              " @impersonate_name=#{@impersonate_name.inspect}" \
              " @quota_project_id=#{@quota_project_id.inspect}" \
              '>'
          end
        end

        private

        def transform_email_to_name(email)
          "projects/-/serviceAccounts/#{email}"
        end
      end
    end
  end
end
