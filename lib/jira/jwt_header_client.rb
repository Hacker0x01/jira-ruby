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
      now = Time.now.to_i
      claim = JIRA::Jwt.build_claims(
        @options[:issuer],
        url,
        http_method.to_s,
        @options[:site] + @options[:context_path].to_s,
        now - 30,
        now + 300
      )

      JWT.encode(claim, @options[:shared_secret], 'HS256')
    end
  end
end
