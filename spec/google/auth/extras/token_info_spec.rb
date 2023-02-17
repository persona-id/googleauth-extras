# frozen_string_literal: true

RSpec.describe Google::Auth::Extras::TokenInfo do
  before do
    Timecop.freeze(Time.at(1676584110))
  end

  describe '.lookup_access_token' do
    subject { described_class.lookup_access_token(token) }

    let(:token) { SecureRandom.hex(100) }

    it 'looks up the token' do
      TokenInfoStubs.stub_lookup_success(access_token: token, expires_in: 290)

      expect(subject).to eq({
        'access_type' => 'online',
        'exp' => 1676584400,
        'expires_in' => 290,
      })
    end

    it 'raises an error when missing expiry' do
      WebMock
        .stub_request(:get, "https://oauth2.googleapis.com/tokeninfo?access_token=#{token}")
        .to_return(
          body: {
            access_type: 'online',
            expires_in: '290',
          }.to_json,
          headers: {
            'Content-Type': 'application/json; charset=UTF-8',
          },
          status: 200,
        )

      expect { subject }.to raise_error(described_class::LookupMalformed, 'Missing token expiry')
    end

    it 'raises an error with malformed input' do
      WebMock
        .stub_request(:get, "https://oauth2.googleapis.com/tokeninfo?access_token=#{token}")
        .to_return(
          body: {
            access_type: 'online',
            exp: (Time.now + 290).to_i.to_s,
            expires_in: '290a',
          }.to_json,
          headers: {
            'Content-Type': 'application/json; charset=UTF-8',
          },
          status: 200,
        )

      expect { subject }.to raise_error(described_class::LookupMalformed)
    end

    it 'raises an error when a lookup fails' do
      TokenInfoStubs.stub_lookup_failure(access_token: token, response_status: 400)

      expect { subject }.to raise_error(described_class::LookupFailed)
    end
  end
end
