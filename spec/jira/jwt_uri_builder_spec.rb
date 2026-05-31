require 'spec_helper'

describe JIRA::JwtClient::JwtUriBuilder do
  subject(:url_builder) do
    JIRA::JwtClient::JwtUriBuilder.new(url, http_method, shared_secret, site, issuer)
  end

  let(:url) { '/foo' }
  let(:http_method) { :get }
  let(:shared_secret) { 'shared_secret' }
  let(:site) { 'http://localhost:2990' }
  let(:issuer) { nil }

  describe '#build' do
    subject { url_builder.build }

    it 'includes the jwt param' do
      expect(subject).to include('?jwt=')
    end

    context 'when the url already contains params' do
      let(:url) { '/foo?expand=projects.issuetypes.fields' }

      it 'includes the jwt param' do
        expect(subject).to include('&jwt=')
      end
    end

    context 'with a complete url' do
      let(:url) { 'http://localhost:2990/rest/api/2/issue/createmeta' }

      it 'includes the jwt param' do
        expect(subject).to include('?jwt=')
      end

      it { is_expected.to start_with('/') }

      it 'contains only one ?' do
        expect(subject.count('?')).to eq(1)
      end
    end

    context 'with a complete url containing a param' do
      let(:url) do
        'http://localhost:2990/rest/api/2/issue/createmeta?expand=projects.issuetypes.fields'
      end

      it 'includes the jwt param' do
        expect(subject).to include('&jwt=')
      end

      it { is_expected.to start_with('/') }

      it 'contains only one ?' do
        expect(subject.count('?')).to eq(1)
      end
    end

    context 'token properties' do
      let(:url) { 'http://localhost:2990/rest/api/2/issue' }

      it 'uses HS256 algorithm' do
        token = subject.match(/jwt=([^&]+)/)[1]
        header = JSON.parse(Base64.decode64(token.split('.').first))
        expect(header['alg']).to eq('HS256')
      end

      it 'uses a short-lived token (5 minute expiry window)' do
        token = subject.match(/jwt=([^&]+)/)[1]
        payload = JWT.decode(token, shared_secret, true, algorithms: ['HS256']).first
        expect(payload['exp'] - payload['iat']).to be <= 330
      end
    end
  end
end
