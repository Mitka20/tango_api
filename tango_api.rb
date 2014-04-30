class TangoApi

	require 'net/https'
	require 'rubygems'
	require 'base64'

	TANGO_SERVER_URL = 'stoken.tango.me'
	TANGO_SERVER_PORT = 8443

	# change constants values to real which you received from Tango
	CERTIFICATES_ROOT = 'path to certificates'
	CA_CERTIFICATE = 'tango_ca.pem'
	P12_CERTIFICATE = 'your_certificate_file_name.p12'
	P12_PASSWORD = 'your certificate password'

	attr_reader :token, :responce

	class TangoConnectionTimeOutException < StandardError;
	end

	def initialize(token)
		@token    = token
	end

	def call
		p12_file           = File.open(p12_file_path, 'rb')
		p12                = OpenSSL::PKCS12.new(p12_file.read, p12_file_password)
		https              = Net::HTTP.new(server_url, server_port)
		https.use_ssl      = true
		#noinspection RubyResolve
		https.verify_mode  = OpenSSL::SSL::VERIFY_NONE
		https.key          = p12.key
		# noinspection RubyResolve
		https.cert         = OpenSSL::X509::Certificate.new p12.certificate
		https.ca_file      = pem_file_path
		https.open_timeout = 10
		https.read_timeout = 10
		body               = {
			'AccessTokenRequest' => {
				'AccessToken' => @token
			}
		}.to_json

		request = Net::HTTP::Post.new('/sdkSso/v1/access.json')
		request.add_field('Content-Type', 'application/json')
		responce_json = https.request(request, body).body
		result    = ActiveSupport::JSON.decode(responce_json)
		@responce = result['AccessTokenResponse']
	end

	def tango_  id
		@responce['TangoId'] if success?
	end

	def auth_token_expired?
		failure? && (reason == 'OUT_OF_VALID_TIME_RANGE' || reason == 'EXPIRED_SDK_TOKEN')
	end

	def success?
		@responce && @responce['Status'] == 'AUTH_SUCCESS'
	end

	def failure?
		!@responce || (@responce && @responce['Status'] == 'AUTH_FAILURE')
	end

	def reason
		@responce['Reason'] if  failure?
	end

	private

	def server_url
		TANGO_SERVER_URL
	end

	def server_port
		TANGO_SERVER_PORT
	end

	def p12_file_path
		CERTIFICATES_ROOT + P12_CERTIFICATE
	end

	def p12_file_password
		P12_PASSWORD
	end

	def pem_file_path
		CERTIFICATES_ROOT + CA_CERTIFICATE
	end

end