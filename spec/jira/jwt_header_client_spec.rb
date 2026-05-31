require 'spec_helper'

describe JIRA::JwtHeaderClient do
  let(:options) do
    {
      site: 'http://localhost:2990',
      context_path: '/jira',
      use_ssl: false,
      ssl_verify_mode: OpenSSL::SSL::VERIFY_NONE,
      read_timeout: 60,
      issuer: 'test-addon',
      shared_secret: 'test-shared-secret'
    }
  end

  subject { described_class.new(options) }

  describe '#make_request' do
    let(:http_conn) { instance_double(Net::HTTP) }
    let(:response) { instance_double(Net::HTTPOK) }

    before do
      allow(Net::HTTP).to receive(:new).and_return(http_conn)
      allow(http_conn).to receive(:use_ssl=)
      allow(http_conn).to receive(:verify_mode=)
      allow(http_conn).to receive(:read_timeout=)
      allow(http_conn).to receive(:request).and_return(response)
      allow(response).to receive(:is_a?).with(Net::HTTPOK).and_return(true)
    end

    it 'adds a JWT Authorization header' do
      subject.make_request(:get, 'http://localhost:2990/jira/rest/api/2/issue/TEST-1', '', {})

      expect(http_conn).to have_received(:request) do |request|
        expect(request['Authorization']).to start_with('JWT ')
      end
    end

    it 'uses HS256 algorithm' do
      subject.make_request(:get, 'http://localhost:2990/jira/rest/api/2/issue/TEST-1', '', {})

      expect(http_conn).to have_received(:request) do |request|
        token = request['Authorization'].sub('JWT ', '')
        header = JSON.parse(Base64.decode64(token.split('.').first))
        expect(header['alg']).to eq('HS256')
      end
    end

    it 'generates a token with short-lived expiry (5 minutes)' do
      subject.make_request(:get, 'http://localhost:2990/jira/rest/api/2/issue/TEST-1', '', {})

      expect(http_conn).to have_received(:request) do |request|
        token = request['Authorization'].sub('JWT ', '')
        payload = JWT.decode(token, 'test-shared-secret', true, algorithms: ['HS256']).first
        expect(payload['exp'] - payload['iat']).to be <= 330
        expect(payload['iss']).to eq('test-addon')
        expect(payload['qsh']).to be_a(String)
      end
    end
  end
end
