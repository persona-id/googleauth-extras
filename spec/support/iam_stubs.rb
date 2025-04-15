# frozen_string_literal: true

module IAMStubs
  extend self

  def stub_generate_access_token(name:, scope:, response_access_token:, response_expire_time:, delegates: nil, lifetime: nil)
    WebMock
      .stub_request(:post, "https://iamcredentials.googleapis.com/v1/#{name}:generateAccessToken")
      .with(body: {
        delegates: delegates,
        lifetime: lifetime,
        scope: scope,
      }.compact.to_json)
      .to_return(
        body: {
          accessToken: response_access_token,
          expireTime: response_expire_time,
        }.to_json,
        headers: {
          'Content-Type': 'application/json; charset=UTF-8',
        },
        status: 200,
      )
  end

  def stub_generate_id_token(audience:, name:, response_token:, delegates: nil, include_email: nil)
    WebMock
      .stub_request(:post, "https://iamcredentials.googleapis.com/v1/#{name}:generateIdToken")
      .with(body: {
        audience: audience,
        delegates: delegates,
        includeEmail: include_email,
      }.compact.to_json)
      .to_return(
        body: {
          token: response_token,
        }.to_json,
        headers: {
          'Content-Type': 'application/json; charset=UTF-8',
        },
        status: 200,
      )
  end

  def stub_sign_jwt(name:, payload:, response_signed_jwt:, delegates: nil)
    WebMock
      .stub_request(:post, "https://iamcredentials.googleapis.com/v1/#{name}:signJwt")
      .with(body: {
        delegates: delegates,
        payload: payload,
      }.compact.to_json)
      .to_return(
        body: {
          signedJwt: response_signed_jwt,
        }.to_json,
        headers: {
          'Content-Type': 'application/json; charset=UTF-8',
        },
        status: 200,
      )
  end
end
