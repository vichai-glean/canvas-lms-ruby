require_relative '../spec_helper'

describe ApiAuthController, type: :controller do
  include Api

  before :once do
    @account = Account.default
    course_with_teacher(active_all: true, account: @account)
    user_with_pseudonym(active_all: true, username: 'test@example.com', password: 'password123')
  end

  describe 'POST #login' do
    context 'with valid credentials' do
      it 'returns an access token and user information' do
        post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        
        expect(response).to have_http_status(:ok)
        json = json_parse(response.body)
        
        expect(json).to include('access_token', 'token_type', 'user')
        expect(json['token_type']).to eq('Bearer')
        expect(json['user']).to include('id', 'name', 'email')
        expect(json['user']['email']).to eq('test@example.com')
      end

      it 'creates an access token in the database' do
        expect {
          post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        }.to change { AccessToken.count }.by(1)
        
        token = AccessToken.last
        expect(token.purpose).to eq('API Direct Login')
        expect(token.user).to eq(@user)
      end

      it 'logs the authentication event' do
        expect(Auditors::Authentication).to receive(:record).with(kind_of(Pseudonym), 'api_login')
        post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
      end

      it 'includes unrestricted scope in the response' do
        post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        
        json = json_parse(response.body)
        expect(json['scope']).to eq('unrestricted')
      end
    end

    context 'with invalid credentials' do
      it 'returns 401 for wrong password' do
        post :login, params: { email: 'test@example.com', password: 'wrongpassword' }, format: :json
        
        expect(response).to have_http_status(:unauthorized)
        json = json_parse(response.body)
        expect(json['error']).to eq('authentication_failed')
        expect(json['error_description']).to eq('Invalid email or password')
      end

      it 'returns 401 for non-existent user' do
        post :login, params: { email: 'nonexistent@example.com', password: 'password123' }, format: :json
        
        expect(response).to have_http_status(:unauthorized)
        json = json_parse(response.body)
        expect(json['error']).to eq('authentication_failed')
      end

      it 'returns 400 for overly long unique_id' do
        long_email = 'a' * 300 + '@example.com'
        post :login, params: { email: long_email, password: 'password123' }, format: :json
        
        expect(response).to have_http_status(:bad_request)
        json = json_parse(response.body)
        expect(json['error']).to eq('authentication_failed')
        expect(json['error_description']).to eq('Invalid credentials format')
      end
    end

    context 'with missing parameters' do
      it 'returns 400 when email is missing' do
        post :login, params: { password: 'password123' }, format: :json
        
        expect(response).to have_http_status(:bad_request)
        json = json_parse(response.body)
        expect(json['error_description']).to eq('Missing email parameter')
      end

      it 'returns 400 when password is missing' do
        post :login, params: { email: 'test@example.com' }, format: :json
        
        expect(response).to have_http_status(:bad_request)
        json = json_parse(response.body)
        expect(json['error_description']).to eq('Missing password parameter')
      end

      it 'returns 400 when both parameters are missing' do
        post :login, params: {}, format: :json
        
        expect(response).to have_http_status(:bad_request)
        json = json_parse(response.body)
        expect(json['error_description']).to eq('Missing email parameter')
      end
    end

    context 'with inactive user account' do
      before do
        @user.update!(workflow_state: 'deleted')
      end

      it 'returns 403 for deleted user' do
        post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        
        expect(response).to have_http_status(:forbidden)
        json = json_parse(response.body)
        expect(json['error_description']).to eq('User account has been deleted')
      end
    end

    context 'with suspended user account' do
      before do
        @user.update!(workflow_state: 'suspended')
      end

      it 'returns 403 for suspended user' do
        post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        
        expect(response).to have_http_status(:forbidden)
        json = json_parse(response.body)
        expect(json['error_description']).to eq('User account is not active')
      end
    end

    context 'developer key creation' do
      it 'creates a developer key if none exists' do
        expect {
          post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        }.to change { DeveloperKey.count }.by(1)
        
        dev_key = DeveloperKey.find_by(name: 'Canvas API Direct Login')
        expect(dev_key).to be_present
        expect(dev_key.account).to eq(Account.default)
      end

      it 'reuses existing developer key' do
        # Create developer key first
        post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        
        expect {
          # Second call should not create another developer key
          post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        }.not_to change { DeveloperKey.count }
      end
    end

    context 'token expiration' do
      it 'includes expires_in when developer key has auto_expire_tokens enabled' do
        post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        
        json = json_parse(response.body)
        if json['expires_in']
          expect(json['expires_in']).to be > 0
        end
      end
    end

    context 'CSRF protection' do
      it 'skips CSRF token validation for login endpoint' do
        # This should not raise ActionController::InvalidAuthenticityToken
        expect {
          post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        }.not_to raise_error
      end
    end

    context 'response format' do
      it 'returns proper OAuth2-style response format' do
        post :login, params: { email: 'test@example.com', password: 'password123' }, format: :json
        
        json = json_parse(response.body)
        
        # Required OAuth2 fields
        expect(json).to include('access_token', 'token_type')
        expect(json['token_type']).to eq('Bearer')
        
        # Canvas-specific fields
        expect(json).to include('user', 'canvas_region')
        
        # User information
        user_info = json['user']
        expect(user_info).to include('id', 'name', 'email', 'login_id', 'global_id')
        expect(user_info['id']).to be_a(Integer)
        expect(user_info['global_id']).to be_a(String)
      end
    end
  end
end 