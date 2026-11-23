class UsersController < ApplicationController
  before_action :require_login

  def show
    @user = User.find_user(params[:id])
    audit_access
  end

  def audit_access
    Rails.logger.info("viewed")
  end
end
