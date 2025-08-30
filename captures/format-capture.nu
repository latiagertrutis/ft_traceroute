#!/usr/bin/nu

def capture_traceroute [cmd :list, prefix :string] {
  let protos = {
  "1": "ICMP"
  "17": "UDP"
  }

  let file = mktemp -p /tmp --suffix .pcap
  let id = job spawn { tshark -i wlan0  -w $file -f "udp dst portrange 33434-33500 or ((icmp[0] == 3 or icmp[0] == 11) and ip[37] == 17)"
  }
  ^$cmd
  sleep 1sec
  job kill $id

  tshark -r $file -l -n -T json | from json | each {|e|
    {
     $"($prefix)_type": ($protos | get ($e | get _source.layers.ip."ip.proto" | into string))    
     $"($prefix)_icmp_type": ($e | get _source.layers.icmp?."icmp.type")    
     $"($prefix)_ttl": ($e | get _source.layers.ip."ip.ttl")
     $"($prefix)_port": ($e | get _source.layers.udp?."udp.dstport")
    }
  }
}

def main [] {
  let orig = capture_traceroute ["traceroute" "-4" "google.com"] "original"
  let mine = capture_traceroute ["./ft_traceroute" "google.com"] "mine"

  $orig | merge $mine

  # Alternate columns between the original and mine
  # ($orig | select original_type)
  # | merge ($mine | select mine_type)
  # | merge ($orig | select original_icmp_type)
  # | merge ($mine | select mine_icmp_type)
  # | merge ($orig | select original_ttl)
  # | merge ($mine | select mine_ttl)
  # | merge ($orig | select original_port)
  # | merge ($mine | select mine_port)
}
