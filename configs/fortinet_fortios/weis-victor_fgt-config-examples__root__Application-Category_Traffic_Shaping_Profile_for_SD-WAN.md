The following configuration uses an application-category-based Traffic Shaping Profile to set bandwidth maximums and guaranteed minimum percentages (as well as priorities) for all traffic destined for the WAN. This configuration assumes you are using SD-WAN, and that your Application Control profiles are monitoring all allowed application categories, and are applied to WAN-destined policies.


```
config system interface
  edit wan1
    set role wan
    set estimated-upstream-bandwidth <upstream-bandwidth-in-kbps>
    set estimated-downstream-bandwidth <upstream-bandwidth-in-kbps>
  next
  edit wan2
    set role wan
    set estimated-upstream-bandwidth <upstream-bandwidth-in-kbps>
    set estimated-downstream-bandwidth <upstream-bandwidth-in-kbps>
  next
  # etc
end  

config firewall traffic-class
    edit 2
        set class-name "default_classid"
    next
    edit 3
        set class-name "business_classid"
    next
    edit 4
        set class-name "cloud.it_classid"
    next
    edit 5
        set class-name "collaboration_classid"
    next
    edit 6
        set class-name "email_classid"
    next
    edit 7
        set class-name "game_classid"
    next
    edit 8
        set class-name "general.interest_classid"
    next
    edit 9
        set class-name "industrial_classid"
    next
    edit 10
        set class-name "mobile_classid"
    next
    edit 11
        set class-name "network.service_classid"
    next
    edit 12
        set class-name "p2p_classid"
    next
    edit 13
        set class-name "proxy_classid"
    next
    edit 14
        set class-name "remote.access_classid"
    next
    edit 15
        set class-name "social.media_classid"
    next
    edit 16
        set class-name "storage.backup_classid"
    next
    edit 17
        set class-name "update_classid"
    next
    edit 18
        set class-name "video/audio_classid"
    next
    edit 19
        set class-name "voip_classid"
    next
    edit 20
        set class-name "web.client_classid"
    next
end

config firewall shaping-profile
    edit "appcat_shaping-prof"
        set default-class-id 2
        config shaping-entries
            edit 1
                set class-id 2
                set priority medium
                set guaranteed-bandwidth-percentage 1
                set maximum-bandwidth-percentage 80
            next
            edit 2
                set class-id 3
                set priority medium
                set guaranteed-bandwidth-percentage 5
                set maximum-bandwidth-percentage 80
            next
            edit 3
                set class-id 4
                set priority medium
                set guaranteed-bandwidth-percentage 3
                set maximum-bandwidth-percentage 80
            next
            edit 4
                set class-id 5
                set guaranteed-bandwidth-percentage 5
                set maximum-bandwidth-percentage 90
            next
            edit 5
                set class-id 6
                set guaranteed-bandwidth-percentage 5
                set maximum-bandwidth-percentage 80
            next
            edit 6
                set class-id 7
                set priority low
                set guaranteed-bandwidth-percentage 1
                set maximum-bandwidth-percentage 50
            next
            edit 7
                set class-id 8
                set priority medium
                set guaranteed-bandwidth-percentage 1
                set maximum-bandwidth-percentage 80
            next
            edit 8
                set class-id 9
                set priority medium
                set guaranteed-bandwidth-percentage 5
                set maximum-bandwidth-percentage 80
            next
            edit 9
                set class-id 10
                set priority medium
                set guaranteed-bandwidth-percentage 1
                set maximum-bandwidth-percentage 80
            next
            edit 10
                set class-id 11
                set priority critical
                set guaranteed-bandwidth-percentage 10
                set maximum-bandwidth-percentage 90
            next
            edit 11
                set class-id 12
                set priority low
                set guaranteed-bandwidth-percentage 1
                set maximum-bandwidth-percentage 50
            next
            edit 12
                set class-id 13
                set guaranteed-bandwidth-percentage 5
                set maximum-bandwidth-percentage 70
            next
            edit 13
                set class-id 14
                set guaranteed-bandwidth-percentage 10
                set maximum-bandwidth-percentage 70
            next
            edit 14
                set class-id 15
                set priority low
                set guaranteed-bandwidth-percentage 5
                set maximum-bandwidth-percentage 50
            next
            edit 15
                set class-id 16
                set priority low
                set guaranteed-bandwidth-percentage 5
                set maximum-bandwidth-percentage 50
            next
            edit 16
                set class-id 17
                set priority low
                set guaranteed-bandwidth-percentage 10
                set maximum-bandwidth-percentage 50
            next
            edit 17
                set class-id 18
                set priority medium
                set guaranteed-bandwidth-percentage 10
                set maximum-bandwidth-percentage 80
            next
            edit 18
                set class-id 19
                set priority top
                set guaranteed-bandwidth-percentage 10
                set maximum-bandwidth-percentage 90
            next
            edit 19
                set class-id 20
                set priority medium
                set guaranteed-bandwidth-percentage 5
                set maximum-bandwidth-percentage 80
            next
        end
    next
end

config firewall shaping-policy
    edit 1
        set name "lan>wan_buisness"
        set service "ALL"
        set app-category 29
        set dstintf "virtual-wan-link"
        set class-id 3
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 2
        set name "lan>wan_cloud.it"
        set service "ALL"
        set app-category 30
        set dstintf "virtual-wan-link"
        set class-id 4
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 3
        set name "lan>wan_collaboration"
        set service "ALL"
        set app-category 28
        set dstintf "virtual-wan-link"
        set class-id 5
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 4
        set name "lan>wan_email"
        set service "ALL"
        set app-category 21
        set dstintf "virtual-wan-link"
        set class-id 6
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 5
        set name "lan>wan_game"
        set service "ALL"
        set app-category 8
        set dstintf "virtual-wan-link"
        set class-id 7
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 6
        set name "lan>wan_general.interest"
        set service "ALL"
        set app-category 12
        set dstintf "virtual-wan-link"
        set class-id 8
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 7
        set name "lan>wan_industrial"
        set service "ALL"
        set app-category 26
        set dstintf "virtual-wan-link"
        set class-id 9
        set srcaddr "lan_subnets"
        set dstaddr "all"
        # set status disable (if you aren't licensed for industrial datase)
    next
    edit 8
        set name "lan>wan_mobile"
        set service "ALL"
        set app-category 31
        set dstintf "virtual-wan-link"
        set class-id 10
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 9
        set name "lan>wan_network.service"
        set service "ALL"
        set app-category 15
        set dstintf "virtual-wan-link"
        set class-id 11
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 10
        set name "lan>wan_p2p"
        set service "ALL"
        set app-category 2
        set dstintf "virtual-wan-link"
        set class-id 12
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 11
        set name "lan>wan_proxy"
        set service "ALL"
        set app-category 6
        set dstintf "virtual-wan-link"
        set class-id 13
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 12
        set name "lan>wan_remote.access"
        set service "ALL"
        set app-category 7
        set dstintf "virtual-wan-link"
        set class-id 14
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 13
        set name "lan>wan_social.media"
        set service "ALL"
        set app-category 23
        set dstintf "virtual-wan-link"
        set class-id 15
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 14
        set name "lan>wan_storage.backup"
        set service "ALL"
        set app-category 22
        set dstintf "virtual-wan-link"
        set class-id 16
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 15
        set name "lan>wan_update"
        set service "ALL"
        set app-category 17
        set dstintf "virtual-wan-link"
        set class-id 17
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 16
        set name "lan>wan_video/audio"
        set service "ALL"
        set app-category 5
        set dstintf "virtual-wan-link"
        set class-id 18
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 17
        set name "lan>wan_voip"
        set service "ALL"
        set app-category 3
        set dstintf "virtual-wan-link"
        set class-id 19
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 18
        set name "lan>wan_web.client"
        set service "ALL"
        set app-category 25
        set dstintf "virtual-wan-link"
        set class-id 20
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
    edit 19
        set name "lan>wan_unknown"
        set service "ALL"
        set app-category 32
        set dstintf "virtual-wan-link"
        set class-id 2
        set srcaddr "lan_subnets"
        set dstaddr "all"
    next
end
```
