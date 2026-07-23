# frozen_string_literal: true

module Google
  module Auth
    module Extras
      # This credential uses a static access token.
      class StaticCredential < Signet::OAuth2::Client
        class AuthorizationExpired < StandardError; end

        attr_reader :quota_project_id

        # A credential using a static access token.
        #
        # @param access_token [String]
        #   The access token to use.
        #
        # @param quota_project_id [String]
        #   The project ID used for quota and billing. This project may be different from
        #   the project used to create the credentials.
        #
        # @param universe_domain [String]
        #   The universe domain of the credential, reported to gRPC google-cloud clients so they
        #   don't raise Gapic::UniverseDomainMismatch. Defaults to googleapis.com.
        #
        def initialize(access_token:, quota_project_id: nil, universe_domain: 'googleapis.com')
          super(
            access_token: access_token,
            expires_at: TokenInfo.lookup_access_token(access_token).fetch('exp'),
            issued_at: nil,
            universe_domain: universe_domain,
          )

          @quota_project_id = quota_project_id
        end

        def fetch_access_token(*)
          raise RefreshNotSupported
        rescue RefreshNotSupported
          # This is a simple trick for getting the cause to be set.
          raise Signet::AuthorizationError, 'Refresh not supported'
        end

        def inspect
          "#<#{self.class.name}" \
            ' @access_token=[REDACTED]' \
            " @expires_at=#{expires_at.inspect}" \
            " @quota_project_id=#{@quota_project_id.inspect}" \
            '>'
        end
      end
    end
  end
end
