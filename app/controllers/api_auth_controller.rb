class ApiAuthController < ApplicationController
  include Api::V1::User
  
  # Skip CSRF protection for stateless API calls
  protect_from_forgery with: :null_session, only: [:login]
  
  # Skip the normal Canvas authentication checks for login endpoint
  skip_before_action :require_user, only: [:login]
  skip_before_action :require_reacceptance_of_terms, only: [:login]
  skip_before_action :load_user, only: [:login]
  
  # Allow API calls on files domain
  skip_before_action :forbid_on_files_domain, only: [:login]

  rescue_from Canvas::OAuth::RequestError, with: :oauth_error
  
  def login
    # Validate required parameters
    return render_error("Missing email parameter", 400) unless params[:email].present?
    return render_error("Missing password parameter", 400) unless params[:password].present?
    
    # Prepare credentials for authentication
    credentials = {
      unique_id: params[:email],
      password: params[:password]
    }
    
    begin
      # Use Canvas's built-in authentication system
      domain_root_account = @domain_root_account || Account.default
      pseudonym = Pseudonym.authenticate(credentials, [domain_root_account.id])
      
      # Handle authentication results
      case pseudonym
      when :impossible_credentials
        return render_error("Invalid credentials format", 400)
      when nil
        return render_error("Invalid email or password", 401)
      when Pseudonym
        # Authentication successful - create access token
        create_api_access_token(pseudonym)
      else
        return render_error("Authentication failed", 401)
      end
      
    rescue => e
      Rails.logger.error("API Authentication error: #{e.message}")
      return render_error("Authentication service temporarily unavailable", 503)
    end
  end
  
  private
  
  def create_api_access_token(pseudonym)
    user = pseudonym.user
    
    # Check if user account is active
    unless user.workflow_state == 'active'
      return render_error("User account is not active", 403)
    end
    
    # Check if user has been deleted
    if user.deleted?
      return render_error("User account has been deleted", 403)
    end
    
    # Create or find a developer key for API access
    domain_root_account = @domain_root_account || Account.default
    developer_key = find_or_create_api_developer_key(domain_root_account)
    
    # Define scopes for the API token
    scopes = default_api_scopes
    
    # Create access token
    access_token = user.access_tokens.create!({
      developer_key: developer_key,
      scopes: scopes,
      purpose: "API Direct Login",
      remember_access: true
    })
    
    access_token.set_permanent_expiration
    access_token.save!
    
    # Prepare response data
    response_data = {
      access_token: access_token.full_token,
      token_type: "Bearer",
      expires_in: access_token.expires_at ? (access_token.expires_at.to_i - Time.now.to_i) : nil,
      scope: scopes ? scopes.join(" ") : "unrestricted",
      user: {
        id: user.id,
        name: user.name,
        email: pseudonym.unique_id,
        login_id: pseudonym.unique_id,
        global_id: user.global_id.to_s,
        avatar_url: user.avatar_url
      },
      canvas_region: Shard.current.database_server.config[:region] || "unknown"
    }
    
    # Add refresh token if available
    if access_token.plaintext_refresh_token
      response_data[:refresh_token] = access_token.plaintext_refresh_token
    end
    
    # Log successful authentication
    Auditors::Authentication.record(pseudonym, "api_login")
    
    render json: response_data, status: :ok
  end
  
  def find_or_create_api_developer_key(account)
    # Look for existing API developer key
    existing_key = DeveloperKey.find_by(
      name: "Canvas API Direct Login",
      account: account
    )
    
    return existing_key if existing_key
    
    # Create new developer key for API access
    scopes = default_api_scopes
    DeveloperKey.create!({
      name: "Canvas API Direct Login",
      account: account,
      auto_expire_tokens: true,
      require_scopes: scopes.present?, # Only require scopes if we're specifying them
      icon_url: nil,
      notes: "Developer key for direct API authentication endpoints",
      scopes: scopes || [] # Use empty array if scopes is nil
    })
  end
  
  def default_api_scopes
    # To allow all scopes, you have three options:
    # 1. Return nil for unrestricted access (recommended - like personal access tokens)
    # 2. Return TokenScopes.all_scopes for explicit all-scope access  
    # 3. Return a custom array of specific scopes for limited access
    
    # Option 1: Unrestricted access (allows all current and future scopes)
    # This is the most flexible and matches Canvas personal access token behavior
    nil
    
    # Option 2: Explicit all scopes (uncomment to use this instead)
    # This grants all currently defined scopes but won't include future scopes
    # TokenScopes.all_scopes
    
    # Option 3: Limited scopes (uncomment to use this instead)
    # This is the most secure but requires careful scope selection
    # [
    #   'url:GET|/api/v1/users/self',
    #   'url:GET|/api/v1/users/:id/profile', 
    #   'url:GET|/api/v1/courses',
    #   'url:GET|/api/v1/courses/:id',
    #   'url:GET|/api/v1/dashboard/dashboard_cards',
    #   'url:POST|/api/v1/courses/:course_id/assignments',
    #   'url:PUT|/api/v1/courses/:course_id/assignments/:id'
    # ]
  end
  
  # Helper method to demonstrate different scope configurations
  def scope_configuration_info
    scopes = default_api_scopes
    case scopes
    when nil
      { type: "unrestricted", description: "Full API access (like personal access tokens)" }
    when Array
      if scopes == TokenScopes.all_scopes
        { type: "all_explicit", description: "All #{scopes.length} current API scopes explicitly granted" }
      else
        { type: "limited", description: "Limited to #{scopes.length} specific scopes" }
      end
    else
      { type: "unknown", description: "Unknown scope configuration" }
    end
  end
  
  def render_error(message, status_code)
    render json: {
      error: "authentication_failed",
      error_description: message
    }, status: status_code
  end
  
  def oauth_error(exception)
    render json: {
      error: exception.error,
      error_description: exception.error_description
    }, status: exception.http_status
  end
end 