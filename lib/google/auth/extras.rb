# frozen_string_literal: true

require 'date'
require 'google/apis/iamcredentials_v1'
require 'signet/oauth_2/client'

require 'google/auth/extras/identity_credential_refresh_patch'
require 'google/auth/extras/impersonated_credential'
require 'google/auth/extras/service_account_jwt_credential'
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

      # A credential that impersonates a service account. For usage with the
      # older style GCP Ruby SDKs from the google-apis-* gems.
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
      # @return [Google::Auth::Extras::ImpersonatedCredential]
      #
      # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
      # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateIdToken
      # @see https://cloud.google.com/iam/docs/create-short-lived-credentials-delegated#sa-credentials-permissions
      # @see https://developers.google.com/identity/protocols/oauth2/scopes
      #
      def impersonated_authorization(
        email_address:,
        base_credentials: nil,
        delegate_email_addresses: nil,
        include_email: nil,
        lifetime: nil,
        quota_project_id: nil,
        scope: nil,
        target_audience: nil
      )
        ImpersonatedCredential.new(
          base_credentials: base_credentials,
          delegate_email_addresses: delegate_email_addresses,
          email_address: email_address,
          include_email: include_email,
          lifetime: lifetime,
          quota_project_id: quota_project_id,
          scope: scope,
          target_audience: target_audience,
        )
      end

      # A credential that impersonates a service account. For usage with the
      # newer style GCP Ruby SDKs from the google-cloud-* gems.
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
      # @return [Google::Auth::Credential<Google::Auth::Extras::ImpersonatedCredential>]
      #
      # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
      # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateIdToken
      # @see https://cloud.google.com/iam/docs/create-short-lived-credentials-delegated#sa-credentials-permissions
      # @see https://developers.google.com/identity/protocols/oauth2/scopes
      #
      def impersonated_credential(
        email_address:,
        base_credentials: nil,
        delegate_email_addresses: nil,
        include_email: nil,
        lifetime: nil,
        quota_project_id: nil,
        scope: nil,
        target_audience: nil
      )
        wrap_authorization(
          impersonated_authorization(
            base_credentials: base_credentials,
            delegate_email_addresses: delegate_email_addresses,
            email_address: email_address,
            include_email: include_email,
            lifetime: lifetime,
            quota_project_id: quota_project_id,
            scope: scope,
            target_audience: target_audience,
          ),
        )
      end

      # A credential that obtains a signed JWT from Google for a service account.
      # For usage with the older style GCP Ruby SDKs from the google-apis-* gems.
      # Also useful for calling IAP-protected endpoints using the Google-managed
      # OAuth client.
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
      # @return [Google::Auth::Extras::ServiceAccountJWTCredential]
      #
      # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt
      # @see https://cloud.google.com/iam/docs/create-short-lived-credentials-delegated#sa-credentials-permissions
      #
      def service_account_jwt_authorization(
        email_address:,
        target_audience:,
        base_credentials: nil,
        delegate_email_addresses: nil,
        issuer: nil,
        lifetime: 3600,
        subject: nil
      )
        ServiceAccountJWTCredential.new(
          base_credentials: base_credentials,
          delegate_email_addresses: delegate_email_addresses,
          email_address: email_address,
          issuer: issuer,
          lifetime: lifetime,
          subject: subject,
          target_audience: target_audience,
        )
      end

      # A credential that obtains a signed JWT from Google for a service account.
      # For usage with the newer style GCP Ruby SDKs from the google-cloud-* gems.
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
      # @return [Google::Auth::Extras::ServiceAccountJWTCredential]
      #
      # @see https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt
      # @see https://cloud.google.com/iam/docs/create-short-lived-credentials-delegated#sa-credentials-permissions
      #
      def service_account_jwt_credential(
        email_address:,
        target_audience:,
        base_credentials: nil,
        delegate_email_addresses: nil,
        issuer: nil,
        lifetime: 3600,
        subject: nil
      )
        wrap_authorization(
          service_account_jwt_authorization(
            base_credentials: base_credentials,
            delegate_email_addresses: delegate_email_addresses,
            email_address: email_address,
            issuer: issuer,
            lifetime: lifetime,
            subject: subject,
            target_audience: target_audience,
          ),
        )
      end

      # A credential using a static access token. For usage with the older
      # style GCP Ruby SDKs from the google-apis-* gems.
      #
      # @param token [String]
      #   The access token to use.
      #
      # @param quota_project_id [String]
      #   The project ID used for quota and billing. This project may be different from
      #   the project used to create the credentials.
      #
      #
      # @return [Google::Auth::Extras::StaticCredential]
      #
      def static_authorization(token, quota_project_id: nil)
        StaticCredential.new(access_token: token, quota_project_id: quota_project_id)
      end

      # A credential using a static access token. For usage with the newer
      # style GCP Ruby SDKs from the google-cloud-* gems.
      #
      # @param token [String]
      #   The access token to use.
      #
      # @param quota_project_id [String]
      #   The project ID used for quota and billing. This project may be different from
      #   the project used to create the credentials.
      #
      # @return [Google::Auth::Credential<Google::Auth::Extras::StaticCredential>]
      #
      def static_credential(token, quota_project_id: nil)
        wrap_authorization(static_authorization(token, quota_project_id: quota_project_id))
      end

      # Take an authorization and turn it into a credential, primarily used
      # for setting up both the old and new style SDKs.
      #
      # @param client [Signet::OAuth2::Client]
      #   Authorization credential to wrap.
      #
      # @return [Google::Auth::Credential]
      #
      def wrap_authorization(client)
        ::Google::Auth::Credentials.new(client)
      end
    end
  end
end
