-----------------snort.lua-----------------
include 'snort_defaults.lua'

stream = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }

wizard = default_wizard

local_rules =
[[
alert tcp (msg:"Confidential Test"; content:"fiden";sid:1;)
]]

ips =
{
rules = local_rules,
}

log_pcap = { limit=0 }
alert_fast = { file = true }
