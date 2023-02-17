# frozen_string_literal: true

module TokenInfoStubs
  extend self

  def stub_lookup_failure(access_token:, response_status:)
    WebMock
      .stub_request(:get, "https://oauth2.googleapis.com/tokeninfo?access_token=#{access_token}")
      .to_return(body: 'failure', headers: {}, status: response_status)
  end

  def stub_lookup_success(access_token:, expires_in:)
    WebMock
      .stub_request(:get, "https://oauth2.googleapis.com/tokeninfo?access_token=#{access_token}")
      .to_return(
        body: {
          access_type: 'online',
          exp: (Time.now + expires_in).to_i.to_s,
          expires_in: expires_in.to_s,
        }.to_json,
        headers: {
          'Content-Type': 'application/json; charset=UTF-8',
        },
        status: 200,
      )
  end
end
