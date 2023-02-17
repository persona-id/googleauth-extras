# frozen_string_literal: true

RSpec.describe Google::Auth::Extras::StaticCredential do
  let(:access_token) { SecureRandom.hex(100) }

  before do
    Timecop.freeze(Time.at(1676584110))
  end

  describe '#initialize' do
    subject { described_class.new(access_token: access_token) }

    it 'correctly sets up the credential' do
      info_stub = TokenInfoStubs.stub_lookup_success(access_token: access_token, expires_in: 290)

      expect(subject.access_token).to eq(access_token)
      expect(subject.expires_at).to eq(Time.at(1676584400))
      expect(subject.issued_at).to be_nil

      expect(subject.expires_within?(60)).to be(false)
      expect(subject.expires_within?(300)).to be(true)

      expect(info_stub).to have_been_requested
    end
  end

  context 'token refresh' do
    it 'does not support refreshing' do
      info_stub = TokenInfoStubs.stub_lookup_success(access_token: access_token, expires_in: 290)

      credential = described_class.new(access_token: access_token)

      expect(info_stub).to have_been_requested

      expect(credential.expires_within?(60)).to be(false)
      expect(credential.needs_access_token?).to be(false)
      expect(credential.apply({})).not_to be_empty

      Timecop.freeze(Time.now + 220)

      expect(credential.expires_within?(60)).to be(false)
      expect(credential.needs_access_token?).to be(false)
      expect(credential.apply({})).not_to be_empty

      Timecop.freeze(Time.now + 20)

      allow(credential).to receive(:fetch_access_token).and_call_original

      expect(credential.expires_within?(60)).to be(true)
      expect(credential.needs_access_token?).to be(true)
      expect { credential.apply({}) }.to raise_error do |error|
        expect(error).to be_a(Signet::AuthorizationError)
        expect(error.cause).to be_a(Google::Auth::Extras::RefreshNotSupported)
      end

      # This is to check we're not getting caught in retry logic.
      expect(credential).to have_received(:fetch_access_token).once
    end
  end
end
