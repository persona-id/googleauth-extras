# frozen_string_literal: true

module Google
  module Auth
    module Extras
      # This credential issues JWTs signed a service account.
      class ServiceAccountJWTCredential < Signet::OAuth2::Client
        include IdentityCredentialRefreshPatch

        # A credential that obtains a signed JWT from Google for a service account.
        #
        # @param base_credentials [Hash, String, Signet::OAuth2::Client]
        #   Credentials to use to sign the JWTs.
        #
        # @param delegate_email_addresses [String, Array<String>]
        #   The email addresses (if any) of intermediate service accounts to reach
        #   the +email_address+ from +base_credentials+.
        #
        # @param email_address [String]
        #   Email of the service account to sign the JWT.
        #
        # @param issuer [String]
        #   The desired value of the iss field on the issued JWT. Defaults to the email_address.
        #
        # @param lifetime [Integers]
        #   The desired lifetime (in seconds) of the JWT before needing to be refreshed.
        #   Defaults to 3600 (1h), adjust as needed given a refresh is automatically
        #   performed when the token less than 60s of remaining life and refresh requires
        #   an additional API call.
        #
        # @param subject [String]
        #   The desired value of the sub field on the issued JWT. Defaults to the email_address.
        #
        # @param target_audience [String]
        #   The audience for the token, such as the API or account that this token grants access to.
        #
        # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt
        # @see https://cloud.google.com/iam/docs/create-short-lived-credentials-delegated#sa-credentials-permissions
        #
        def initialize(
          email_address:,
          target_audience:,
          base_credentials: nil,
          delegate_email_addresses: nil,
          issuer: nil,
          lifetime: 3600,
          subject: nil
        )
          super(client_id: target_audience, target_audience: target_audience)

          @iam_credentials_service = Google::Apis::IamcredentialsV1::IAMCredentialsService.new.tap do |ics|
            ics.authorization = base_credentials if base_credentials
          end

          @jwt_issuer = issuer || email_address
          @jwt_lifetime = lifetime
          @jwt_subject = subject || email_address

          @sa_delegates = Array(delegate_email_addresses).map do |email|
            transform_email_to_name(email)
          end

          @sa_name = transform_email_to_name(email_address)
        end

        def fetch_access_token(*)
          now = Time.now.to_i

          request = Google::Apis::IamcredentialsV1::SignJwtRequest.new(
            payload: JSON.dump(
              aud: target_audience,
              exp: now + @jwt_lifetime,
              iat: now,
              iss: @jwt_issuer,
              sub: @jwt_subject,
            ),
          )

          # The Google SDK doesn't like nil repeated values, but be careful with others as well.
          request.delegates = @sa_delegates unless @sa_delegates.empty?

          response = @iam_credentials_service.sign_service_account_jwt(@sa_name, request)

          {
            id_token: response.signed_jwt,
          }
        end

        def inspect
          "#<#{self.class.name}" \
            " @expires_at=#{expires_at.inspect}" \
            " @id_token=#{@id_token ? '[REDACTED]' : 'nil'}" \
            " @jwt_issuer=#{@jwt_issuer.inspect}" \
            " @jwt_lifetime=#{@jwt_lifetime.inspect}" \
            " @jwt_subject=#{@jwt_subject.inspect}" \
            " @sa_delegates=#{@sa_delegates.inspect}" \
            " @sa_name=#{@sa_name.inspect}" \
            " @target_audience=#{@target_audience.inspect}" \
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
