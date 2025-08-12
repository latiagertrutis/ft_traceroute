#!/usr/bin/nu

def main [f: string] {
  let protos = {
  "1": "ICMP"
  "17": "UDP"
  }
  open $f | each {|e|
    {
     type: ($protos | get ($e | get _source.layers.ip."ip.proto" | into string))    
     icmp_type: ($e | get _source.layers.icmp?."icmp.type")    
     ttl: ($e | get _source.layers.ip."ip.ttl")
     port: ($e | get _source.layers.udp?."udp.dstport")
    }
  }
}
