require 'spec_helper'

describe JIRA::Jwt do
  describe '.canonicalize_uri' do
    def canonicalize(path, base_path = '')
      uri = URI.parse("http://host#{path}")
      base_uri = URI.parse("http://host#{base_path}")
      described_class.canonicalize_uri(uri, base_uri)
    end

    it 'strips the base context path' do
      expect(canonicalize('/jira/rest/api/2/issue', '/jira')).to eq('/rest/api/2/issue')
    end

    it 'strips a multi-segment context path' do
      expect(canonicalize('/my/app/rest/resource', '/my/app')).to eq('/rest/resource')
    end

    it 'returns / when path equals the context path' do
      expect(canonicalize('/jira', '/jira')).to eq('/')
    end

    it 'returns / for an empty path after stripping' do
      expect(canonicalize('/jira/', '/jira')).to eq('/')
    end

    it 'returns / for a bare root path with no context' do
      expect(canonicalize('/', '')).to eq('/')
    end

    it 'removes the trailing slash from non-root paths' do
      expect(canonicalize('/rest/api/2/', '')).to eq('/rest/api/2')
    end

    it 'preserves the trailing slash for root /' do
      expect(canonicalize('/', '')).to eq('/')
    end

    it 'ensures a leading slash after stripping' do
      expect(canonicalize('/jira/rest', '/jira')).to start_with('/')
    end

    it 'escapes & in path segments to %26' do
      expect(canonicalize('/rest/a&b/resource', '')).to eq('/rest/a%26b/resource')
    end

    it 'handles no context path' do
      expect(canonicalize('/rest/api/2/project', '')).to eq('/rest/api/2/project')
    end

    it 'does not double-strip when path does not start with context' do
      expect(canonicalize('/other/rest/api', '/jira')).to eq('/other/rest/api')
    end
  end

  describe '.canonicalize_query_string' do
    it 'returns empty string for nil query' do
      expect(described_class.canonicalize_query_string(nil)).to eq('')
    end

    it 'returns empty string for empty query' do
      expect(described_class.canonicalize_query_string('')).to eq('')
    end

    it 'sorts parameters alphabetically by key' do
      result = described_class.canonicalize_query_string('z=1&a=2&m=3')
      expect(result).to eq('a=2&m=3&z=1')
    end

    it 'strips the jwt parameter' do
      result = described_class.canonicalize_query_string('foo=bar&jwt=secret123&baz=qux')
      expect(result).to eq('baz=qux&foo=bar')
    end

    it 'returns empty string when jwt is the only parameter' do
      result = described_class.canonicalize_query_string('jwt=secret123')
      expect(result).to eq('')
    end

    it 'sorts repeated parameter values and joins with comma' do
      result = described_class.canonicalize_query_string('color=blue&color=red&color=green')
      expect(result).to eq('color=blue,green,red')
    end

    it 'encodes spaces as %20 not +' do
      result = described_class.canonicalize_query_string('msg=hello+world')
      expect(result).to eq('msg=hello%20world')
    end

    it 'does not encode tildes' do
      result = described_class.canonicalize_query_string('path=~user')
      expect(result).to eq('path=~user')
    end

    it 'percent-encodes special characters in values' do
      result = described_class.canonicalize_query_string('q=a/b')
      expect(result).to eq('q=a%2Fb')
    end

    it 'encodes keys with CGI.escape (spaces as +)' do
      result = described_class.canonicalize_query_string('my+key=value')
      expect(result).to eq('my+key=value')
    end

    it 'handles a complex multi-param query with repeated keys' do
      query = 'expand=projects.issuetypes.fields&type=bug&type=task&jwt=ignore'
      result = described_class.canonicalize_query_string(query)
      expect(result).to eq('expand=projects.issuetypes.fields&type=bug,task')
    end
  end

  describe '.create_canonical_request' do
    it 'joins method, path, and query with &' do
      result = described_class.create_canonical_request(
        'http://host/jira/rest/api/2/issue?status=open',
        'GET',
        'http://host/jira'
      )
      expect(result).to eq('GET&/rest/api/2/issue&status=open')
    end

    it 'uppercases the HTTP method' do
      result = described_class.create_canonical_request('/rest/api', 'post', '')
      expect(result).to eq('POST&/rest/api&')
    end

    it 'strips context path from a full URL' do
      result = described_class.create_canonical_request(
        'http://localhost:2990/jira/rest/api/2/project',
        'GET',
        'http://localhost:2990/jira'
      )
      expect(result).to eq('GET&/rest/api/2/project&')
    end

    it 'handles query parameters with sorting and jwt stripping' do
      result = described_class.create_canonical_request(
        'http://host/ctx/rest?z=1&a=2&jwt=token',
        'GET',
        'http://host/ctx'
      )
      expect(result).to eq('GET&/rest&a=2&z=1')
    end

    it 'handles a path-only URI' do
      result = described_class.create_canonical_request('/rest/api/2/issue', 'PUT', '')
      expect(result).to eq('PUT&/rest/api/2/issue&')
    end

    it 'handles root path with context stripping' do
      result = described_class.create_canonical_request(
        'http://host/jira',
        'GET',
        'http://host/jira'
      )
      expect(result).to eq('GET&/&')
    end
  end

  describe '.build_claims' do
    let(:issuer) { 'my-addon-key' }
    let(:url) { 'http://localhost:2990/jira/rest/api/2/issue' }
    let(:http_method) { 'GET' }
    let(:base_url) { 'http://localhost:2990/jira' }
    let(:issued_at) { 1_000_000 }
    let(:expires) { 1_000_060 }

    subject do
      described_class.build_claims(issuer, url, http_method, base_url, issued_at, expires)
    end

    it 'includes the issuer' do
      expect(subject[:iss]).to eq('my-addon-key')
    end

    it 'includes issued_at timestamp' do
      expect(subject[:iat]).to eq(1_000_000)
    end

    it 'includes expiration timestamp' do
      expect(subject[:exp]).to eq(1_000_060)
    end

    it 'computes qsh as SHA-256 of the canonical request' do
      canonical = described_class.create_canonical_request(url, http_method, base_url)
      expected_qsh = Digest::SHA256.hexdigest(canonical)
      expect(subject[:qsh]).to eq(expected_qsh)
    end

    it 'defaults expires to issued_at + 60 when not provided' do
      claims = described_class.build_claims(issuer, url, http_method, base_url, 5000)
      expect(claims[:exp]).to eq(5060)
    end

    it 'merges additional attributes' do
      claims = described_class.build_claims(
        issuer, url, http_method, base_url, issued_at, expires,
        sub: 'admin', context: { user: { key: 'admin' } }
      )
      expect(claims[:sub]).to eq('admin')
      expect(claims[:context]).to eq({ user: { key: 'admin' } })
    end

    it 'produces different qsh for different HTTP methods on the same URL' do
      get_claims = described_class.build_claims(issuer, url, 'GET', base_url, issued_at, expires)
      post_claims = described_class.build_claims(issuer, url, 'POST', base_url, issued_at, expires)
      expect(get_claims[:qsh]).not_to eq(post_claims[:qsh])
    end

    it 'produces different qsh for different query parameters' do
      url_a = 'http://host/ctx/rest?a=1'
      url_b = 'http://host/ctx/rest?a=2'
      claims_a = described_class.build_claims(issuer, url_a, 'GET', 'http://host/ctx', issued_at, expires)
      claims_b = described_class.build_claims(issuer, url_b, 'GET', 'http://host/ctx', issued_at, expires)
      expect(claims_a[:qsh]).not_to eq(claims_b[:qsh])
    end

    it 'produces the same qsh regardless of query parameter order' do
      url_a = 'http://host/ctx/rest?b=2&a=1'
      url_b = 'http://host/ctx/rest?a=1&b=2'
      claims_a = described_class.build_claims(issuer, url_a, 'GET', 'http://host/ctx', issued_at, expires)
      claims_b = described_class.build_claims(issuer, url_b, 'GET', 'http://host/ctx', issued_at, expires)
      expect(claims_a[:qsh]).to eq(claims_b[:qsh])
    end

    it 'ignores the jwt query param when computing qsh' do
      url_with_jwt = 'http://host/ctx/rest?foo=bar&jwt=old_token'
      url_without_jwt = 'http://host/ctx/rest?foo=bar'
      claims_a = described_class.build_claims(issuer, url_with_jwt, 'GET', 'http://host/ctx', issued_at, expires)
      claims_b = described_class.build_claims(issuer, url_without_jwt, 'GET', 'http://host/ctx', issued_at, expires)
      expect(claims_a[:qsh]).to eq(claims_b[:qsh])
    end
  end
end
