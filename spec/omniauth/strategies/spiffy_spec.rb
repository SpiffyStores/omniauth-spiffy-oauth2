require 'omniauth-spiffy-oauth2'
require 'base64'

describe OmniAuth::Strategies::Spiffy do
  before :each do
    @request = double('Request',
                      :env => { })
    @request.stub(:params) { {} }
    @request.stub(:cookies) { {} }

    @client_id = '123'
    @client_secret = '53cr3tz'
    @options = {:client_options => {:site => 'https://example.spiffystores.com'}}
  end

  subject do
    args = [@client_id, @client_secret, @options].compact
    OmniAuth::Strategies::Spiffy.new(nil, *args).tap do |strategy|
      strategy.stub(:request) { @request }
      strategy.stub(:session) { {} }
    end
  end

  describe '#fix_https' do
    it 'replaces http scheme by https' do
      @options = {:client_options => {:site => 'http://foo.bar/'}}
      subject.fix_https
      subject.options[:client_options][:site].should eq('https://foo.bar/')
    end

    it 'replaces http scheme by https with an immutable string' do
      @options = {:client_options => {:site => 'http://foo.bar/'.freeze}}
      subject.fix_https
      subject.options[:client_options][:site].should eq('https://foo.bar/')
    end

    it 'does not replace https scheme' do
      @options = {:client_options => {:site => 'https://foo.bar/'}}
      subject.fix_https
      subject.options[:client_options][:site].should eq('https://foo.bar/')
    end
  end

  describe '#client' do
    it 'has correct spiffy_stores site' do
      subject.client.site.should eq('https://example.spiffystores.com')
    end

    it 'has correct authorize url' do
      subject.client.options[:authorize_url].should eq('/admin/oauth/authorize')
    end

    it 'has correct token url' do
      subject.client.options[:token_url].should eq('/admin/oauth/access_token')
    end
  end

  describe '#callback_url' do
    it "returns value from #callback_url" do
      url = 'http://auth.myapp.com/auth/callback'
      @options = {:callback_url => url}
      subject.callback_url.should eq(url)
    end

    it "defaults to callback" do
      url_base = 'http://auth.request.com'
      @request.stub(:url) { "#{url_base}/page/path" }
      @request.stub(:scheme) { 'http' }
      subject.stub(:script_name) { "" } # to not depend from Rack env
      subject.callback_url.should eq("#{url_base}/auth/spiffy/callback")
    end
  end

  describe '#authorize_params' do
    it 'includes default scope for read_products' do
      subject.authorize_params.should be_a(Hash)
      subject.authorize_params[:scope].should eq('read_products')
    end

    it 'includes custom scope' do
      @options = {:scope => 'write_products'}
      subject.authorize_params.should be_a(Hash)
      subject.authorize_params[:scope].should eq('write_products')
    end
  end

  describe '#uid' do
    it 'returns the shop' do
      subject.uid.should eq('example.spiffystores.com')
    end
  end

  describe '#credentials' do
    before :each do
      @access_token = double('OAuth2::AccessToken')
      @access_token.stub(:token)
      @access_token.stub(:expires?)
      @access_token.stub(:expires_at)
      @access_token.stub(:refresh_token)
      subject.stub(:access_token) { @access_token }
    end

    it 'returns a Hash' do
      subject.credentials.should be_a(Hash)
    end

    it 'returns the token' do
      @access_token.stub(:token) { '123' }
      subject.credentials['token'].should eq('123')
    end

    it 'returns the expiry status' do
      @access_token.stub(:expires?) { true }
      subject.credentials['expires'].should eq(true)

      @access_token.stub(:expires?) { false }
      subject.credentials['expires'].should eq(false)
    end

  end

  describe '#valid_site?' do
    it 'returns true if the site contains .spiffystores.com' do
      @options = {:client_options => {:site => 'http://foo.spiffystores.com/'}}
      subject.valid_site?.should eq(true)
    end

    it 'returns false if the site does not contain .spiffystores.com' do
      @options = {:client_options => {:site => 'http://foo.example.com/'}}
      subject.valid_site?.should eq(false)
    end

    it 'uses configurable option for spiffy_stores_domain' do
      @options = {:client_options => {:site => 'http://foo.example.com/'}, :spiffy_stores_domain => 'example.com'}
      subject.valid_site?.should eq(true)
    end

    it 'allows custom port for spiffy_stores_domain' do
      @options = {:client_options => {:site => 'http://foo.example.com:3456/'}, :spiffy_stores_domain => 'example.com:3456'}
      subject.valid_site?.should eq(true)
    end
  end

  describe '#valid_permissions?' do
    let(:associated_user) do
      {}
    end

    let(:token) do
      {
        'associated_user' => associated_user,
      }
    end

    it 'returns false if there is no token' do
      expect(subject.valid_permissions?(nil)).to be_falsey
    end

    context 'with per_user_permissions is present' do
      before do
        @options = @options.merge(per_user_permissions: true)
      end

      context 'when token does not have associated user' do
        let(:associated_user) { nil }

        it 'return false' do
          expect(subject.valid_permissions?(token)).to be_falsey
        end
      end

      context 'when token has associated user' do
        it 'return true' do
          expect(subject.valid_permissions?(token)).to be_truthy
        end
      end
    end

    context 'with per_user_permissions is false' do
      before do
        @options = @options.merge(per_user_permissions: false)
      end

      context 'when token does not have associated user' do
        let(:associated_user) { nil }

        it 'return true' do
          expect(subject.valid_permissions?(token)).to be_truthy
        end
      end

      context 'when token has associated user' do
        it 'return false' do
          expect(subject.valid_permissions?(token)).to be_falsey
        end
      end
    end

    context 'with per_user_permissions is nil' do
      before do
        @options = @options.merge(per_user_permissions: nil)
      end

      context 'when token does not have associated user' do
        let(:associated_user) { nil }

        it 'return true' do
          expect(subject.valid_permissions?(token)).to be_truthy
        end
      end

      context 'when token has associated user' do
        it 'return false' do
          expect(subject.valid_permissions?(token)).to be_falsey
        end
      end
    end
  end
end
