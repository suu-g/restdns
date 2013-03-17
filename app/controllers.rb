Restdns.controllers  do
  get '/' do
    send_file "public/index.html"
  end

  get '/public/?' do
    send_file "public/index.html"
  end

  get '/:url/?' do
    res = simple_dns_request(params[:url])
    res
  end

  get '/:url/v4/?' do
    res = simple_dns_request_v4(params[:url])
    res
  end

  get '/:url/v6/?' do
    res = simple_dns_request_v6(params[:url])
    res
  end

  get '/:url/:type/?' do
    res = dns_request_json(params[:url], params[:type].upcase)
    res
  end

  delete '/' do
    # not implemented yet
  end

  #not_found do
  #  redirect '/index.html'
  #end
  # get :index, :map => "/foo/bar" do
  #   session[:foo] = "bar"
  #   render 'index'
  # end

  # get :sample, :map => "/sample/url", :provides => [:any, :js] do
  #   case content_type
  #     when :js then ...
  #     else ...
  # end

  # get :foo, :with => :id do
  #   "Maps to url '/foo/#{params[:id]}'"
  # end

  # get "/example" do
  #   "Hello world!"
  # end
end
