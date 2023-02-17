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
end
