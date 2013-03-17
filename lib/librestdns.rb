#!/usr/local/bin/ruby
# version 0.4
require 'resolv'
require 'ipaddr'

require 'rubygems'
require 'json'
require 'dnsruby'

$type_table = {
  'A' =>  Dnsruby::RR::IN::A,
  'AAAA' =>  Dnsruby::RR::IN::AAAA,
  'WKS' =>  Dnsruby::RR::IN::WKS,
  'SRV' =>  Dnsruby::RR::IN::SRV,
  'MX' =>  Dnsruby::RR::MX,
  'NS' =>  Dnsruby::RR::NS,
  'TXT' =>  Dnsruby::RR::TXT,
  'ANY' =>  Dnsruby::RR::ANY,
  'SOA' =>  Dnsruby::RR::SOA,
  'CNAME' =>  Dnsruby::RR::CNAME,
  'PTR' =>  Dnsruby::RR::PTR,
  'DNSKEY' => Dnsruby::RR::DNSKEY,
  'RRSIG' => Dnsruby::RR::RRSIG,
  'DS' => Dnsruby::RR::DS
}

def simple_dns_request(host)
  res = Resolv.getaddresses(host)
  r = ""
  for e in res
    r += e
    r += "\n"
  end
  return r.chomp.downcase
rescue Resolv::ResolvError
  return "0.0.0.0"
  return r
end
def simple_dns_request_v4(host)
  begin
    r = Resolv.getaddress(host)
  rescue Resolv::ResolvError
    r = "0.0.0.0"
  end
  return r
end
def simple_dns_request_v6(host)
  res = dns_request(host, 'AAAA')
  if res.nil?
    return "::"
  end
  dic = parse_request(res, host)

  if dic.has_key?('AAAA') then
    return dic['AAAA'][0].to_s.downcase
  else
    return "::"
  end

  return "::"
end

def dns_request(host, type)
  #
  # Cache TO BE IMPLEMENTED
  # 
  # Request by "ANY", cache result and choose which to give back
  # ... That's what this function has to do.
  #       right now it is implemented in a naiiiive way.
  #

  t = nil

  case type
  when 'X'
    # works same as `dig -x`
    #t = Resolv::DNS::Resource::IN::PTR
    t = "PTR"
    host = IPAddr.new(host).reverse
  else
    if ! $type_table.has_key?(type)
      return nil
    end
    t = type
  end

  # if the hostname have more than two dots on the tail, remove them
  # if the hostname doesn't have a dot on the tail, add it
  # '.' == 46
  if host[-1] == 46
    while host[-2] == 46
      host.chop!
    end
  else
    host += "."
  end

  return Dnsruby::DNS::new::getresources(host, t)
  
rescue Dnsruby::ResolvError
  return nil
rescue ArgumentError
  return nil
end


def parse_request(res, host)
  dic = {}
  dic['hostname'] = host
  if res.nil? 
    return dic
  end

  for req in res do
    case req 
    when $type_table['A']
      k = 'A'
      v = req.address
    when $type_table['AAAA']
      k = 'AAAA'
      v = req.address.to_s.downcase
    when $type_table['MX']
      k = 'MX'
      v = {'preference' => req.preference, 'exchange' => req.exchange.to_s}
    when $type_table['NS']
      k = 'NS'
      v = req.domainname
    when $type_table['PTR']
      k = 'PTR'
      v = req.domainname
    when $type_table['CNAME']
      k = 'CNAME'
      v = req.name
    when $type_table['SRV']
      k = 'SRV'
      v = {
        'port' => req.port, 
        'priority' => req.priority,
        'target' => req.target,
        'weight' => req.weight
      }
    when $type_table['WKS']
      k = 'WKS'
      v = {
        'address' => req.address,
        'bitmap' => req.bitmap ? 1 : 0,
        'protocol' => req.protocol
      }
    when $type_table['DNSKEY']
      k = 'DNSKEY'
      v = {
        'algorithm' => req.algorithm.to_s,
        'flags' => req.flags.to_s,
        'key' => [req.key].pack("m").chomp,
        'key_tag' => req.key_tag().to_s,
        'protocol' => req.protocol
      }
    when $type_table['RRSIG']
      k = 'RRSIG'
      v = {
        'algorithm' => req.algorithm.to_s,
        'expiration' => req.expiration,
        'inception' => req.inception,
        'key_tag' => req.key_tag,
        'labels' => req.labels,
        'original_ttl' => req.original_ttl,
        'signature' => [req.signature].pack("m").chomp,
        'signers_name' => req.signers_name,
        'type_covered' => req.type_covered
      }
    when $type_table['DS']
      k = 'DS'
      v = {
        'algorithm' => req.algorithm.to_s,
        'digest' => req.digest.to_s,
        'digest_type' => req.digest_type,
        'digestbin' => req.digestbin.unpack("H*")[0],
        'key_tag' => req.key_tag.to_s
      }
    when $type_table['SOA']
      k = 'SOA'
      v = {
        'serial'  => req.serial,
        'refresh' => req.refresh,
        'retry'   => req.retry,
        'expire'  => req.expire,
        'minimum' => req.minimum,  # actually used as negative-cache
        'mname'   => req.mname,
        'rname'   => "" # don't let the spammers get address by this service
        # 'rname'   => req.rname.to_s   # don't let the spammers get address easier
      }
    when $type_table['TXT']
      # TXT is given as an array
      # Therefore the routine is a bit different from others
      k = 'TXT'
      v = req.strings
      if dic.key?(k)
        dic[k] += v
      else
        dic[k] = v
      end
      next
    else
    end
      
    if dic.key?(k)
      dic[k] << v
    else
      dic[k] = [v]
    end
  end

  return dic
end

def dns_request_json(host, type)
#      simple example for json
#  {
#      "hostname" : "example.com",
#      "a"        : ["192.0.2.24"],
#      "aaaa"     : ["2001:db8::24"],
#      "mx"       : [
#                    {"preference" : 100, "exchange" : "mx2.example.com"},
#                    {"preference" : 10, "exchange" : "mx.example.com"}
#                   ],
#      "ns"       : [
#                    {"name" : }
#                   ],
#      "txt"      : ["v=spf1 +ip4:192.0.2.0/24 +ip6:2001:db8::/64 ~all"]
#  }
#      or,
#  {
#      "ip"       : "192.0.2.24",
#      "reverse"  : "24.2.0.192.in-addr.arpa",
#      "hostname" : "host.example.com"
#  }
  res = dns_request(host, type)
  dic = parse_request(res, host)
  return JSON.pretty_generate(dic)

end

def dns_request_xml()
  # TO BE IMPLEMENTED
  # SOMEWHERE IN THE FUTURE...
end
def dns_request_msgpack()
  # TO BE IMPLEMENTED
  # SOMEWHERE IN THE FUTURE...
end

