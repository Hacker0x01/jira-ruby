require 'jira/jwt'

module JIRA
  class JwtHeaderClient < HttpClient
    def make_request(http_method, url, body = '', headers = {})
      @http_method = http_method

      super(http_method, url, body, headers.merge(jwt_header(@http_method, url)))
    end

    def make_multipart_request(url, data, headers = {})
      @http_method = :post

      super(url, data, headers.merge(jwt_header(@http_method, url)))
    end

    private

    def jwt_header(http_method, url)
      { 'Authorization' => "JWT #{jwt_token(http_method, url)}" }
    end

    def jwt_token(http_method, url)
      claim = JIRA::Jwt.build_claims(
        @options[:issuer],
        url,
        http_method.to_s,
        @options[:site],
        (Time.now - 60).to_i,
        (Time.now + 86_400).to_i
      )

      JWT.encode(claim, @options[:shared_secret])
    end
  end
end
