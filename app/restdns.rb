#!/usr/local/bin/ruby
require 'rubygems'
require 'sinatra'
load '_restdns.rb'

# set :port, 4946

get '/' do
  send_file "/public/index.html"
end

get '/public/?' do
  send_file "/public/index.html"
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

not_found do
  redirect '/'
end

