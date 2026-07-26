/*
   Maltrail APT Threat Feed - YARA Rules
   Source: https://github.com/stamparm/maltrail
   
   IMPORTANT: These are automatically generated rules for threat detection
   Review and test before deploying to production
*/

import "hash"
import "pe"

rule APT__12 {
    meta:
        description = "Indicators associated with APT 12"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt12, apt-c-12, bluemushroom"

    strings:
        $domain0 = "icc.ignorelist.com" nocase
        $domain1 = "video.csmcpr.com" nocase
        $ip2 = "178.128.110.214"

    condition:
        any of them
}

rule APT__17 {
    meta:
        description = "Indicators associated with APT 17"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt17, apt-c-17, blackcoffee"

    strings:
        $domain0 = "equitaligaiustizia.it" nocase
        $domain1 = "meeting.equitaligaiustizia.it" nocase
        $domain2 = "news.jusched.net" nocase
        $domain3 = "themicrosoftnow.com" nocase
        $domain4 = "translate.wordraference.com" nocase

    condition:
        any of them
}

rule APT__18 {
    meta:
        description = "Indicators associated with APT 18"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "128.er1620.com" nocase
        $domain1 = "223-25-233-248.revdns.8toinfinity.com.sg" nocase
        $domain2 = "admin.er1620.com" nocase
        $domain3 = "exp0day.com" nocase
        $domain4 = "ftp.exp0day.com" nocase
        $domain5 = "gmail.bkz88.com" nocase
        $domain6 = "good.myftp.org" nocase
        $domain7 = "hello.mjw.bz" nocase
        $domain8 = "info.imly.org" nocase
        $domain9 = "login.3bz.org" nocase
        $domain10 = "logo.mjw.bz" nocase
        $domain11 = "suck.er1620.com" nocase
        $domain12 = "test.3bz.org" nocase
        $domain13 = "zip.redirectme.net" nocase
        $ip14 = "223.25.233.248"

    condition:
        any of them
}

rule APT__1877TEAM {
    meta:
        description = "Indicators associated with APT 1877TEAM"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "1877.krd" nocase
        $domain1 = "1877.team" nocase
        $domain2 = "4567987654345265.tk" nocase
        $domain3 = "asadohostma.cf" nocase
        $domain4 = "asadohostma.tk" nocase
        $domain5 = "balotelaras.gq" nocase
        $domain6 = "bjigcdrfbbcx.ml" nocase
        $domain7 = "bjigcdrfbbcx.tk" nocase
        $domain8 = "bruthoosbxyxio.gq" nocase
        $domain9 = "bruthoosbxyxio.tk" nocase
        $domain10 = "bsidbxiooohzu.ga" nocase
        $domain11 = "bsidbxiooohzu.gq" nocase
        $domain12 = "bsidbxiooohzu.ml" nocase
        $domain13 = "buhgdkurd444.ga" nocase
        $domain14 = "coalermallwive.ga" nocase
        $domain15 = "dxfcvhhgfgcv.dnsfailover.net" nocase
        $domain16 = "facebookmessages.serveuser.com" nocase
        $domain17 = "facebooktie.faqserv.com" nocase
        $domain18 = "forever0g.tk" nocase
        $domain19 = "gartytrgfredsw.sexidude.com" nocase
        $domain20 = "gatasawatoyo.dumb1.com" nocase
        $domain21 = "ghiiidueebsxiis.ml" nocase
        $domain22 = "ghiiidueebsxiis.tk" nocase
        $domain23 = "hgtgerfdrty.onedumb.com" nocase
        $domain24 = "hsushzidooonsnx.gq" nocase
        $domain25 = "htetryfugyioiyut.ml" nocase
        $domain26 = "hunchifigkf.wikaba.com" nocase
        $domain27 = "huncho.ml" nocase
        $domain28 = "hunchooo.zzux.com" nocase
        $domain29 = "hunchoooof.2waky.com" nocase
        $domain30 = "incxzsdcuuwqag.serveuser.com" nocase
        $domain31 = "inlinkedlnmessagesdigiter.serveuser.com" nocase
        $domain32 = "jagajaga.ga" nocase
        $domain33 = "jfueytg7yghg.ga" nocase
        $domain34 = "jhdfgdjkdg.dynamic-dns.net" nocase
        $domain35 = "jhssales.dynamic-dns.net" nocase
        $domain36 = "jhuyghft.dynamic-dns.net" nocase
        $domain37 = "jihugkyfjtdsrytsrd.cf" nocase
        $domain38 = "jihugkyfjtdsrytsrd.gq" nocase
        $domain39 = "jnhbvgcfxdzsdzdsxd.dns2.us" nocase
        $domain40 = "juyhtrdwski.sexidude.com" nocase
        $domain41 = "kbbkbkuu.dynamic-dns.net" nocase
        $domain42 = "kjuhygtrfdewsa.onedumb.com" nocase
        $domain43 = "linkedlndeed.fartit.com" nocase
        $domain44 = "linkup.pics" nocase
        $domain45 = "mail.bsabshjlinacafs.serveuser.com" nocase
        $domain46 = "mail.facebookmessages.serveuser.com" nocase
        $domain47 = "mail.guyyyeyb.youdontcare.com" nocase
        $domain48 = "mail.inlinkedlnmessagesdigiter.serveuser.com" nocase
        $domain49 = "mail.jhdfgdjkdg.dynamic-dns.net" nocase
        $domain50 = "mail.jhuyghft.dynamic-dns.net" nocase
        $domain51 = "mail.juyhtrdwski.sexidude.com" nocase
        $domain52 = "mail.kasawaraswgu.yourtrap.com" nocase
        $domain53 = "mail.mnfdxcvbn.cleansite.info" nocase
        $domain54 = "mail.ohssbxxwaqmbccxk.x24hr.com" nocase
        $domain55 = "mail.oiytiuopiuy.almostmy.com" nocase
        $domain56 = "mail.roboroboo.dumb1.com" nocase
        $domain57 = "mail.rywrhsg.dns05.com" nocase
        $domain58 = "mail.sdhgdfth.zzux.com" nocase
        $domain59 = "mail.snhyjhakua.x24hr.com" nocase
        $domain60 = "makolo.ml" nocase
        $domain61 = "mangersales.zyns.com" nocase
        $domain62 = "marketingadmin.port25.biz" nocase
        $domain63 = "mnjgyutjfo.longmusic.com" nocase
        $domain64 = "mssjhgwe.toh.info" nocase
        $domain65 = "nmjvutdwrw.dns04.com" nocase
        $domain66 = "oiuryhgyefdter.gq" nocase
        $domain67 = "salogo.gq" nocase
        $domain68 = "saqwijfde4ojhbyvubi.b0tnet.com" nocase
        $domain69 = "servercheck.zyns.com" nocase
        $domain70 = "shop.1877.team" nocase
        $domain71 = "social.1877.team" nocase
        $domain72 = "steetdre6iazwed.tk" nocase
        $domain73 = "stiwebbro.ml" nocase
        $domain74 = "stupuviijvftuiu.cf" nocase
        $domain75 = "supplypurchase.dns04.com" nocase
        $domain76 = "sxdfcghvjhbkkredirec.serveusers.com" nocase
        $domain77 = "tgfr43e98uj43ef.ml" nocase
        $domain78 = "tools.1877.team" nocase
        $domain79 = "torontos.ga" nocase
        $domain80 = "tradefaregoods.dns04.com" nocase
        $domain81 = "tube.1877.team" nocase
        $domain82 = "ukyudrst.zyns.com" nocase
        $domain83 = "unconditional.gq" nocase
        $domain84 = "uqjswjwswsjwsh.serveuser.com" nocase
        $domain85 = "uytresgfgh.changeip.co" nocase
        $domain86 = "vanuboutst.cf" nocase
        $domain87 = "vanuboutst.ml" nocase
        $domain88 = "wpojgbjffy444.cf" nocase
        $domain89 = "yjksvjdbjdbjjda.cf" nocase
        $domain90 = "yjksvjdbjdbjjda.ga" nocase
        $domain91 = "yjksvjdbjdbjjda.ml" nocase
        $domain92 = "yjksvjdbjdbjjda.tk" nocase
        $domain93 = "zone.1877.team" nocase

    condition:
        any of them
}

rule APT__23 {
    meta:
        description = "Indicators associated with APT 23"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt23, apt-c-23, micropsia"

    strings:
        $domain0 = "1jve.com" nocase
        $domain1 = "9oo91e.co" nocase
        $domain2 = "aamir-khan.site" nocase
        $domain3 = "accaunts-googlc.com" nocase
        $domain4 = "account-gocgle.com" nocase
        $domain5 = "account-googlc.com" nocase
        $domain6 = "accountforuser.website" nocase
        $domain7 = "accountforusers.website" nocase
        $domain8 = "accounts-gocgle.com" nocase
        $domain9 = "accounts-goog-le.com" nocase
        $domain10 = "accounts-googlc.com" nocase
        $domain11 = "accountusers.website" nocase
        $domain12 = "accuant-googlc.com" nocase
        $domain13 = "acount-manager.com" nocase
        $domain14 = "acount-manager.info" nocase
        $domain15 = "acount-manager.net" nocase
        $domain16 = "acount-manager.org" nocase
        $domain17 = "activedardash.club" nocase
        $domain18 = "adamnews.for.ug" nocase
        $domain19 = "advanced-files.club" nocase
        $domain20 = "ahnlabin.com" nocase
        $domain21 = "akashipro.com" nocase
        $domain22 = "al-amalhumandevelopment.com" nocase
        $domain23 = "alain.ps" nocase
        $domain24 = "alishatnixon.site" nocase
        $domain25 = "alisonparker.club" nocase
        $domain26 = "alttaeb.info" nocase
        $domain27 = "amanda-hart.website" nocase
        $domain28 = "amyacunningham.us" nocase
        $domain29 = "android-settings.info" nocase
        $domain30 = "angeladeloney.info" nocase
        $domain31 = "anifondnet.club" nocase
        $domain32 = "anna-sanchez.online" nocase
        $domain33 = "ansonwhitmore.live" nocase
        $domain34 = "apkapps.pro" nocase
        $domain35 = "apkapps.site" nocase
        $domain36 = "app-market.online" nocase
        $domain37 = "appchecker.us" nocase
        $domain38 = "appppure.info" nocase
        $domain39 = "appppure.net" nocase
        $domain40 = "appppure.pro" nocase
        $domain41 = "apppure.info" nocase
        $domain42 = "apps-download.store" nocase
        $domain43 = "apps-market.site" nocase
        $domain44 = "apps-store.online" nocase
        $domain45 = "appuree.info" nocase
        $domain46 = "arnani.info" nocase
        $domain47 = "arthursaito.club" nocase
        $domain48 = "artlifelondon.com" nocase
        $domain49 = "aryastark.info" nocase
        $domain50 = "aslaug-sigurd.info" nocase
        $domain51 = "assets-acc.club" nocase
        $domain52 = "assistenza-dati.com" nocase
        $domain53 = "autlook.live" nocase
        $domain54 = "barairhate.com" nocase
        $domain55 = "baysidebride.net" nocase
        $domain56 = "bbalignit.com" nocase
        $domain57 = "bbc-learning.com" nocase
        $domain58 = "beauty-dance.net" nocase
        $domain59 = "beauty-msg.com" nocase
        $domain60 = "belcherjacky.info" nocase
        $domain61 = "bellamy-bob.life" nocase
        $domain62 = "bestbitloly.website" nocase
        $domain63 = "billy-bones.info" nocase
        $domain64 = "bitgames.world" nocase
        $domain65 = "black-honey.club" nocase
        $domain66 = "blaxaplayer.com" nocase
        $domain67 = "bob-turco.website" nocase
        $domain68 = "bourneliam.info" nocase
        $domain69 = "brian-garcia.work" nocase
        $domain70 = "brooksprofessional.com" nocase
        $domain71 = "bruce-ess.com" nocase
        $domain72 = "businessessmarketed.com" nocase
        $domain73 = "businessesspromoted.com" nocase
        $domain74 = "businessessreviewed.com" nocase
        $domain75 = "businessesssimplified.com" nocase
        $domain76 = "businessesstransformed.com" nocase
        $domain77 = "businessservicesinc.net" nocase
        $domain78 = "buymicrosft.com" nocase
        $domain79 = "cajaaekhart.club" nocase
        $domain80 = "calculator-1e016.appspot.com" nocase
        $domain81 = "calculator-1e016.firebaseio.com" nocase
        $domain82 = "camilleoconnell.website" nocase
        $domain83 = "carbon-tour.com" nocase
        $domain84 = "caroline-nina.com" nocase
        $domain85 = "cassy-gray.club" nocase
        $domain86 = "catchansee.com" nocase
        $domain87 = "cathy-seliver.icu" nocase
        $domain88 = "cecilia-dobrev.com" nocase
        $domain89 = "cecilia-gilbert.com" nocase
        $domain90 = "cerseilannister.info" nocase
        $domain91 = "chad-jessie.info" nocase
        $domain92 = "charmainellauzier.host" nocase
        $domain93 = "chat-14bb1.appspot.com" nocase
        $domain94 = "chat-14bb1.firebaseio.com" nocase
        $domain95 = "chat-often.com" nocase
        $domain96 = "chat-update.live" nocase
        $domain97 = "christopher.fun" nocase
        $domain98 = "claire-browne.info" nocase
        $domain99 = "clarke-griffin.info" nocase
        $ip100 = "198.54.117.211"
        $ip101 = "198.54.117.212"
        $ip102 = "198.54.117.215"
        $ip103 = "198.54.117.217"
        $ip104 = "198.54.117.218"
        $ip105 = "68.65.121.44"
        $ip106 = "68.65.121.44"

    condition:
        any of them
}

rule APT__27 {
    meta:
        description = "Indicators associated with APT 27"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "emissary panda, apt27, apt 27"

    strings:
        $domain0 = "24h.tinthethaoi.com" nocase
        $domain1 = "265g.site" nocase
        $domain2 = "36106g.com" nocase
        $domain3 = "88tech.me" nocase
        $domain4 = "activity.maacson.com" nocase
        $domain5 = "adobesys.com" nocase
        $domain6 = "aibeichen.cn" nocase
        $domain7 = "amazonawsgarages.com" nocase
        $domain8 = "analyaze.s3amazonbucket.com" nocase
        $domain9 = "analysis.windowstearns.com" nocase
        $domain10 = "api.youkesdt.asia" nocase
        $domain11 = "atlas-sian.net" nocase
        $domain12 = "awvsf7esh.dellrescue.com" nocase
        $domain13 = "bbs.maacson.com" nocase
        $domain14 = "bbs.sonypsps.com" nocase
        $domain15 = "buy.teamviewsoft.com" nocase
        $domain16 = "cat.toonganuh.com" nocase
        $domain17 = "cdn.laokpl.com" nocase
        $domain18 = "center.veryssl.org" nocase
        $domain19 = "chatsecure.uk.to" nocase
        $domain20 = "chatsecurelite.uk.to" nocase
        $domain21 = "chatsecurelite.us.to" nocase
        $domain22 = "chinhsech.com" nocase
        $domain23 = "chototem.com" nocase
        $domain24 = "chrome-upgrade.com" nocase
        $domain25 = "ckvyk.com" nocase
        $domain26 = "ckvyk.net" nocase
        $domain27 = "cloud.cutepaty.com" nocase
        $domain28 = "cloudservicesdevc.tk" nocase
        $domain29 = "coco.sodexoa.com" nocase
        $domain30 = "conglyan.com" nocase
        $domain31 = "cooodkord.com" nocase
        $domain32 = "cophieu.dcsvnqvmn.com" nocase
        $domain33 = "coreders.com" nocase
        $domain34 = "cornm100.io" nocase
        $domain35 = "cutepaty.com" nocase
        $domain36 = "cv3sa.gicp.net" nocase
        $domain37 = "daikynguyen21.com" nocase
        $domain38 = "dangquanwatch.com" nocase
        $domain39 = "dataanalyticsclub.com" nocase
        $domain40 = "datacache.cloudservicesdevc.tk" nocase
        $domain41 = "dcsvnqvmn.com" nocase
        $domain42 = "dev.gitlabs.me" nocase
        $domain43 = "diendanlichsu.com" nocase
        $domain44 = "dn.dulichbiendao.org" nocase
        $domain45 = "dns.itbaydns.com" nocase
        $domain46 = "dongaruou.com" nocase
        $domain47 = "dongnain.com" nocase
        $domain48 = "dulichculao.com" nocase
        $domain49 = "encryptit.qc.to" nocase
        $domain50 = "fasterwall.com" nocase
        $domain51 = "files.amazonawsgarages.com" nocase
        $domain52 = "gateway.vietbaotinmoi.com" nocase
        $domain53 = "ggfnv.com" nocase
        $domain54 = "giaitrinuoc.com" nocase
        $domain55 = "giaoxuchuson.com" nocase
        $domain56 = "gitlabs.me" nocase
        $domain57 = "gj.wxb2568.cn" nocase
        $domain58 = "google-updata.tk" nocase
        $domain59 = "govmn.tk" nocase
        $domain60 = "halong.dulichculao.com" nocase
        $domain61 = "hanghoa.trenduang.com" nocase
        $domain62 = "hcm.vietbaonam.com" nocase
        $domain63 = "hcmuafgh.com" nocase
        $domain64 = "hn.dulichbiendao.org" nocase
        $domain65 = "i1mc.xyz" nocase
        $domain66 = "images.webprogobest.com" nocase
        $domain67 = "info.coreders.com" nocase
        $domain68 = "jgkgv.net" nocase
        $domain69 = "jiqun.i1mc.xyz" nocase
        $domain70 = "jira.atlas-sian.net" nocase
        $domain71 = "jkncj.com" nocase
        $domain72 = "khinhte.chinhsech.com" nocase
        $domain73 = "kinhte.chototem.com" nocase
        $domain74 = "kinhtevanhoa.com" nocase
        $domain75 = "kmbk8.hicp.net" nocase
        $domain76 = "language.wikaba.com" nocase
        $domain77 = "laokpl.com" nocase
        $domain78 = "laomoodwin.com" nocase
        $domain79 = "laovoanew.com" nocase
        $domain80 = "lat.conglyan.com" nocase
        $domain81 = "linux.updatelive-oline.com" nocase
        $domain82 = "livehelp100services.com" nocase
        $domain83 = "livehelpl00service.com" nocase
        $domain84 = "livelyhellp.chat" nocase
        $domain85 = "login.dangquanwatch.com" nocase
        $domain86 = "login.diendanlichsu.com" nocase
        $domain87 = "login.giaoxuchuson.com" nocase
        $domain88 = "login.thanhnienthegioi.com" nocase
        $domain89 = "login.vietnamfar.com" nocase
        $domain90 = "luan.conglyan.com" nocase
        $domain91 = "maacson.com" nocase
        $domain92 = "max.cornm100.io" nocase
        $domain93 = "microlynconline.com" nocase
        $domain94 = "mildupdate.com" nocase
        $domain95 = "ministop14.com" nocase
        $domain96 = "motivation.neighboring.site" nocase
        $domain97 = "mychau.dongnain.com" nocase
        $domain98 = "myvandyke.net" nocase
        $domain99 = "new.sggpnews.com" nocase
        $ip100 = "103.243.26.213"
        $ip101 = "103.79.77.200"
        $ip102 = "104.168.211.246"
        $ip103 = "104.168.236.46"
        $ip104 = "115.214.104.26"
        $ip105 = "139.180.216.65"
        $ip106 = "154.93.7.99"
        $ip107 = "185.12.45.134"
        $ip108 = "27.124.26.136"
        $ip109 = "27.124.26.136"
        $ip110 = "35.187.148.253"
        $ip111 = "35.220.135.85"
        $ip112 = "38.54.119.239"
        $ip113 = "45.142.214.193"
        $ip114 = "45.32.33.17"
        $ip115 = "45.77.250.141"
        $ip116 = "47.75.49.32"
        $ip117 = "80.92.206.158"
        $ip118 = "85.204.74.143"
        $ip119 = "87.98.190.184"
        $ip120 = "89.35.178.105"

    condition:
        any of them
}

rule APT__30 {
    meta:
        description = "Indicators associated with APT 30"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "appsecnic.com" nocase
        $domain1 = "aseanm.com" nocase
        $domain2 = "autoapec.com" nocase
        $domain3 = "bigfixtools.com" nocase
        $domain4 = "bluesixnine.com" nocase
        $domain5 = "cbkjdxf.com" nocase
        $domain6 = "creammemory.com" nocase
        $domain7 = "gordeneyes.com" nocase
        $domain8 = "iapfreecenter.com" nocase
        $domain9 = "kabadefender.com" nocase
        $domain10 = "km-nyc.com" nocase
        $domain11 = "km153.com" nocase
        $domain12 = "lisword.com" nocase
        $domain13 = "newpresses.com" nocase
        $domain14 = "techmicrost.com" nocase
        $ip15 = "103.233.10.152"
        $ip16 = "103.233.10.152"
        $ip17 = "103.233.10.152"
        $ip18 = "172.247.197.189"

    condition:
        any of them
}

rule APT__33 {
    meta:
        description = "Indicators associated with APT 33"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "admindirector.com" nocase
        $domain1 = "akadnsplugin.com" nocase
        $domain2 = "alsalam.ddns.net" nocase
        $domain3 = "aramcojobs.ddns.net" nocase
        $domain4 = "availsqaapi.premieredigital.net" nocase
        $domain5 = "azure-dnszones.com" nocase
        $domain6 = "backupaccount.net" nocase
        $domain7 = "backupnet.ddns.net" nocase
        $domain8 = "becomestateman.com" nocase
        $domain9 = "bistbotsproxies.ddns.net" nocase
        $domain10 = "boeing.servehttp.com" nocase
        $domain11 = "businessscards.com" nocase
        $domain12 = "cardchsk.com" nocase
        $domain13 = "cardkuys.com" nocase
        $domain14 = "ceoadminoffice.com" nocase
        $domain15 = "chromup.com" nocase
        $domain16 = "customermgmt.net" nocase
        $domain17 = "dailystudy.org" nocase
        $domain18 = "digitalcodecrafters.com" nocase
        $domain19 = "diplomatsign.com" nocase
        $domain20 = "dyn-corp.ddns.net" nocase
        $domain21 = "dyncorp.ddns.net" nocase
        $domain22 = "eventmonitoring.org" nocase
        $domain23 = "fucksaudi.ddns.net" nocase
        $domain24 = "gefurrinn.com" nocase
        $domain25 = "global-careers.org" nocase
        $domain26 = "googlechromehost.ddns.net" nocase
        $domain27 = "googlmail.net" nocase
        $domain28 = "groupchiefexecutive.com" nocase
        $domain29 = "hellocookies.ddns.net" nocase
        $domain30 = "hyperservice.ddns.net" nocase
        $domain31 = "imap-outlook.com" nocase
        $domain32 = "inboxsync.org" nocase
        $domain33 = "lovememories.org" nocase
        $domain34 = "mailsarchive.com" nocase
        $domain35 = "managehelpdesk.com" nocase
        $domain36 = "managementdirector.com" nocase
        $domain37 = "microsoftupdated.com" nocase
        $domain38 = "microsoftupdated.net" nocase
        $domain39 = "moreonlineshopping.com" nocase
        $domain40 = "mynetwork.cf" nocase
        $domain41 = "mynetwork.ddns.net" nocase
        $domain42 = "mynetwork2.ddns.net" nocase
        $domain43 = "mypsh.ddns.net" nocase
        $domain44 = "mywinnetwork.ddns.net" nocase
        $domain45 = "n3tc4t.hopto.com" nocase
        $domain46 = "newhost.hopto.org" nocase
        $domain47 = "ngaaksa.ddns.net" nocase
        $domain48 = "ngaaksa.ga" nocase
        $domain49 = "ngaaksa.sytes.net" nocase
        $domain50 = "njrat12.ddns.net" nocase
        $domain51 = "ocsp-support.com" nocase
        $domain52 = "officemngt.com" nocase
        $domain53 = "osupd.com" nocase
        $domain54 = "phpencryptssl.com" nocase
        $domain55 = "powersafety.org" nocase
        $domain56 = "qualitweb.com" nocase
        $domain57 = "relaxingsports.com" nocase
        $domain58 = "remote-server.ddns.net" nocase
        $domain59 = "remserver.ddns.net" nocase
        $domain60 = "sabic-co.ddns.net" nocase
        $domain61 = "saharapcc.ddns.net" nocase
        $domain62 = "securityupdated.com" nocase
        $domain63 = "servhost.hopto.org" nocase
        $domain64 = "service-avant.com" nocase
        $domain65 = "service-eset.com" nocase
        $domain66 = "service-essential.com" nocase
        $domain67 = "service-explorer.com" nocase
        $domain68 = "service-houston.com" nocase
        $domain69 = "service-norton.com" nocase
        $domain70 = "service-search.info" nocase
        $domain71 = "simsoshop.com" nocase
        $domain72 = "sipchem.ddns.net" nocase
        $domain73 = "smtpauths.com" nocase
        $domain74 = "smtpsync.com" nocase
        $domain75 = "srvhost.servehttp.com" nocase
        $domain76 = "suncocity.com" nocase
        $domain77 = "support-newyork.com" nocase
        $domain78 = "svcexplores.com" nocase
        $domain79 = "syn.broadcaster.rocks" nocase
        $domain80 = "teamnj.ddns.net" nocase
        $domain81 = "theworldjob.org" nocase
        $domain82 = "times-sync.com" nocase
        $domain83 = "tokensetting.com" nocase
        $domain84 = "trojan1117.hopto.org" nocase
        $domain85 = "truelogon.com" nocase
        $domain86 = "update-sec.com" nocase
        $domain87 = "update-symantec.com" nocase
        $domain88 = "urlmanage.com" nocase
        $domain89 = "vinnellarabia.myftp.org" nocase
        $domain90 = "whiteelection.com" nocase
        $domain91 = "windowsx.sytes.net" nocase
        $domain92 = "world-careers.org" nocase
        $domain93 = "wwwgooglecom.sytes.net" nocase
        $domain94 = "xtreme.hopto.org" nocase
        $domain95 = "younesadams.ddns.net" nocase
        $domain96 = "za158155.ddns.net" nocase
        $domain97 = "zandelshop.com" nocase
        $domain98 = "zeverco.com" nocase
        $ip99 = "188.166.55.116"

    condition:
        any of them
}

rule APT__37 {
    meta:
        description = "Indicators associated with APT 37"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt37, apt-c-37, geumseong121"

    strings:
        $domain0 = "0member-services.hol.es" nocase
        $domain1 = "1006ieudneu.atwebpages.com" nocase
        $domain2 = "1980food.co.kr" nocase
        $domain3 = "1995ieudneu.atwebpages.com" nocase
        $domain4 = "acddesigns.com.au" nocase
        $domain5 = "acl-medias.fr" nocase
        $domain6 = "acount-pro.club" nocase
        $domain7 = "acount-pro.live" nocase
        $domain8 = "adamnews.for.ug" nocase
        $domain9 = "admin.mobonad.com" nocase
        $domain10 = "admin.primgs.lol" nocase
        $domain11 = "ahnlab.check.pe.hu" nocase
        $domain12 = "ahooc.com" nocase
        $domain13 = "alireza.traderfree.online" nocase
        $domain14 = "anlysis-info.xyz" nocase
        $domain15 = "annstyle.ru" nocase
        $domain16 = "api.jquery.services" nocase
        $domain17 = "app-wallet.com" nocase
        $domain18 = "app.cleanos.online" nocase
        $domain19 = "asia-studies.net" nocase
        $domain20 = "attachdown.000webhostapp.com" nocase
        $domain21 = "attachdownload.000webhostapp.com" nocase
        $domain22 = "attachdownload.99on.com" nocase
        $domain23 = "atusay.lat" nocase
        $domain24 = "bajut.pro" nocase
        $domain25 = "bellissues.live" nocase
        $domain26 = "benefitinfo.live" nocase
        $domain27 = "benefitinfo.pro" nocase
        $domain28 = "benefiturl.pro" nocase
        $domain29 = "bian0151.cafe24.com" nocase
        $domain30 = "bigfilemail.net" nocase
        $domain31 = "bignaver.com" nocase
        $domain32 = "bigwnet.com" nocase
        $domain33 = "bitwoll.com" nocase
        $domain34 = "blockochain.info" nocase
        $domain35 = "btcaes2.duckdns.org" nocase
        $domain36 = "busyday.atwebpages.com" nocase
        $domain37 = "buttyfly.000webhostapp.com" nocase
        $domain38 = "careagency.online" nocase
        $domain39 = "carnegieinsider.com" nocase
        $domain40 = "cdns.jquery.services" nocase
        $domain41 = "cerebrovascular.net" nocase
        $domain42 = "cexrout.com" nocase
        $domain43 = "change-pw.com" nocase
        $domain44 = "checkprofie.com" nocase
        $domain45 = "cheth.lol" nocase
        $domain46 = "christinadudley.com" nocase
        $domain47 = "cleanos.online" nocase
        $domain48 = "clonesec.us" nocase
        $domain49 = "cloudnaver.com" nocase
        $domain50 = "cloudocument.com" nocase
        $domain51 = "cloudsecurityservice.net" nocase
        $domain52 = "cloudwebappservice.com" nocase
        $domain53 = "cndsoft.co.kr" nocase
        $domain54 = "colorncopy.co.kr" nocase
        $domain55 = "com-change.pw" nocase
        $domain56 = "com-serviceround.info" nocase
        $domain57 = "conference.outlook-offices.com" nocase
        $domain58 = "cra-receivenow.online" nocase
        $domain59 = "crareceive.site" nocase
        $domain60 = "crilts.cfd" nocase
        $domain61 = "crwellfood.com" nocase
        $domain62 = "ctquast.com" nocase
        $domain63 = "da3da3.duckdns.org" nocase
        $domain64 = "daehoat.com" nocase
        $domain65 = "dailycloudservice.com" nocase
        $domain66 = "dailynk.us" nocase
        $domain67 = "darklights.store" nocase
        $domain68 = "dataviewering.com" nocase
        $domain69 = "daum-protect.com" nocase
        $domain70 = "daum-store.com" nocase
        $domain71 = "daum.sytes.net" nocase
        $domain72 = "daumhelp.net" nocase
        $domain73 = "dauurn.net" nocase
        $domain74 = "day-post.com" nocase
        $domain75 = "deioncube.biz" nocase
        $domain76 = "delivernaver.com" nocase
        $domain77 = "delivers-security.com" nocase
        $domain78 = "delivers-security.net" nocase
        $domain79 = "depositurl.co" nocase
        $domain80 = "depositurl.lat" nocase
        $domain81 = "dialy-post.com" nocase
        $domain82 = "diplomatictraining.com" nocase
        $domain83 = "direct.traderfree.online" nocase
        $domain84 = "dnsservice.esy.es" nocase
        $domain85 = "doc-view.work" nocase
        $domain86 = "document-package.online" nocase
        $domain87 = "documentpackage.space" nocase
        $domain88 = "documentpackages.link" nocase
        $domain89 = "documentpackages.online" nocase
        $domain90 = "documentpackages.space" nocase
        $domain91 = "documentpackages.store" nocase
        $domain92 = "documentserver.site" nocase
        $domain93 = "documentviewingcom.com" nocase
        $domain94 = "docx1.b4a.app" nocase
        $domain95 = "dounn.net" nocase
        $domain96 = "dovvn-mail.com" nocase
        $domain97 = "down-drive.me" nocase
        $domain98 = "down-error.com" nocase
        $domain99 = "download-apks.com" nocase
        $ip100 = "144.172.106.66"
        $ip101 = "208.85.16.88"

    condition:
        any of them
}

rule APT__38 {
    meta:
        description = "Indicators associated with APT 38"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "a.updatesinfos.com" nocase
        $domain1 = "b.updatesinfos.com" nocase
        $domain2 = "bitdefs.ignorelist.com" nocase
        $domain3 = "gphi-adhaswe.xyz" nocase
        $domain4 = "gphi-gsaeyheq.top" nocase
        $domain5 = "gphi.site" nocase
        $domain6 = "ip1.gphi-adhaswe.xyz" nocase
        $domain7 = "ip1.gphi-gsaeyheq.top" nocase
        $domain8 = "ip1.s.gphi.site" nocase
        $domain9 = "ip2.s.gphi.site" nocase
        $domain10 = "updatesinfos.com" nocase

    condition:
        any of them
}

rule APT__45 {
    meta:
        description = "Indicators associated with APT 45"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "84.38.134.56"
        $ip1 = "84.38.134.56"

    condition:
        any of them
}

rule APT__48 {
    meta:
        description = "Indicators associated with APT 48"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-48"

    strings:
        $domain0 = "efb.recume.ink" nocase
        $domain1 = "klp.recume.ink" nocase
        $domain2 = "mnb.recume.ink" nocase
        $domain3 = "panbaiclu.com" nocase
        $domain4 = "recume.ink" nocase
        $domain5 = "vpn616865750.softether.net" nocase
        $ip6 = "185.243.112.142"

    condition:
        any of them
}

rule APT__5 {
    meta:
        description = "Indicators associated with APT 5"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-5"

    strings:
        $domain0 = "4jslg.diggfunny.com" nocase
        $domain1 = "alyac.org" nocase
        $domain2 = "bbs.edsplan.com" nocase
        $domain3 = "bbs.ezxsoft.com" nocase
        $domain4 = "bomuls.com" nocase
        $domain5 = "cache.mindplat.com" nocase
        $domain6 = "daumfan.com" nocase
        $domain7 = "dig.edsplan.com" nocase
        $domain8 = "diggfunny.com" nocase
        $domain9 = "dnf.diggfunny.com" nocase
        $domain10 = "download.bomuls.com" nocase
        $domain11 = "duamlive.com" nocase
        $domain12 = "edsplan.com" nocase
        $domain13 = "expre.dyndns.tv" nocase
        $domain14 = "ezxsoft.com" nocase
        $domain15 = "fh.edsplan.com" nocase
        $domain16 = "file1.nprotects.org" nocase
        $domain17 = "finalcover.com" nocase
        $domain18 = "fr.duamlive.com" nocase
        $domain19 = "gl.edsplan.com" nocase
        $domain20 = "l.finalcover.com" nocase
        $domain21 = "mindplat.com" nocase
        $domain22 = "n.duamlive.com" nocase
        $domain23 = "natefan.com" nocase
        $domain24 = "nateon.duamlive.com" nocase
        $domain25 = "nprotects.org" nocase
        $domain26 = "path.alyac.org" nocase
        $domain27 = "pc.nprotects.org" nocase
        $domain28 = "projectxz.com" nocase
        $domain29 = "ro.diggfunny.com" nocase
        $domain30 = "smartnet.edsplan.com" nocase
        $domain31 = "soucesp.com" nocase
        $domain32 = "t.finalcover.com" nocase
        $domain33 = "text.edsplan.com" nocase
        $domain34 = "trendmicros.net" nocase
        $domain35 = "unix.edsplan.com" nocase
        $domain36 = "update.alyac.org" nocase
        $domain37 = "update.nprotects.org" nocase
        $domain38 = "us.duamlive.com" nocase
        $domain39 = "vn.edsplan.com" nocase
        $domain40 = "wf.edsplan.com" nocase
        $ip41 = "116.127.121.41"

    condition:
        any of them
}

rule APT__60 {
    meta:
        description = "Indicators associated with APT 60"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-60, apt-q-12, spyglace"

    strings:
        $domain0 = "juanjuan.cesy.top" nocase
        $domain1 = "milfbate.com" nocase
        $domain2 = "nimdsrt.com" nocase
        $domain3 = "rammenale.com" nocase
        $ip4 = "103.187.26.174"
        $ip5 = "103.187.26.175"
        $ip6 = "103.187.26.176"
        $ip7 = "103.187.26.177"
        $ip8 = "203.174.87.18"

    condition:
        any of them
}

rule APT__68 {
    meta:
        description = "Indicators associated with APT 68"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-68, apt-q-15"

    strings:
        $domain0 = "softwarediskservice.com" nocase
        $domain1 = "star.softwarediskservice.com" nocase

    condition:
        any of them
}

rule APT__73 {
    meta:
        description = "Indicators associated with APT 73"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "eraleig ransomware"

    strings:
        $domain0 = "bashe4aec32kr6zbifwd5x6xgjsmhg4tbowrbx4pneqhc5mqooyifpid.onion" nocase
        $domain1 = "basheqtvzqwz4vp6ks5lm2ocq7i6tozqgf6vjcasj4ezmsy4bkpshhyd.onion" nocase
        $domain2 = "basherq53eniermxovo3bkduw5qqq5bkqcml3qictfmamgvmzovykyqd.onion" nocase
        $domain3 = "eraleignews.com" nocase
        $domain4 = "fleqwmg7xnanypt5km2m75l72q7nlcvlp2m4sdmgjxorsn6tb3zyp3qd.onion" nocase
        $domain5 = "ns1.eraleignews.com" nocase
        $domain6 = "ns2.eraleignews.com" nocase
        $domain7 = "ns3.eraleignews.com" nocase
        $domain8 = "ns4.eraleignews.com" nocase
        $domain9 = "qcgv5tfer4f46ns6ohh72zeyyh5uavoiybypzpt3lmwk5ecyqykptgqd.onion" nocase
        $domain10 = "wn6vonooq6fggjdgyocp7bioykmfjket7sbp47cwhgubvowwd7ws5pyd.onion" nocase

    condition:
        any of them
}

rule APT_AOQINDRAGON {
    meta:
        description = "Indicators associated with APT AOQINDRAGON"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "Heyoka, Mongall, UNC94"

    strings:
        $domain0 = "adsoft.name" nocase
        $domain1 = "back.satunusa.org" nocase
        $domain2 = "baomoi.vnptnet.info" nocase
        $domain3 = "bbw.fushing.org" nocase
        $domain4 = "bca.zdungk.com" nocase
        $domain5 = "bkav.manlish.net" nocase
        $domain6 = "bkav.welikejack.com" nocase
        $domain7 = "bkavonline.vnptnet.info" nocase
        $domain8 = "bluesky1234.com" nocase
        $domain9 = "bush2015.net" nocase
        $domain10 = "cl.weststations.com" nocase
        $domain11 = "cloundvietnam.com" nocase
        $domain12 = "comnnet.net" nocase
        $domain13 = "cpt.vnptnet.inf" nocase
        $domain14 = "cvb.hotcup.pw" nocase
        $domain15 = "dellyou.com" nocase
        $domain16 = "dinhk.net" nocase
        $domain17 = "dns.foodforthought1.com" nocase
        $domain18 = "dns.lioncity.top" nocase
        $domain19 = "dns.satunusa.org" nocase
        $domain20 = "dns.zdungk.com" nocase
        $domain21 = "ds.vdcvn.com" nocase
        $domain22 = "ds.xrayccc.top" nocase
        $domain23 = "dungk.com" nocase
        $domain24 = "facebookmap.top" nocase
        $domain25 = "fbcl2.adsoft.name" nocase
        $domain26 = "fbcl2.softad.net" nocase
        $domain27 = "flower2.yyppmm.com" nocase
        $domain28 = "followag.org" nocase
        $domain29 = "foodforthought1.com" nocase
        $domain30 = "fushing.org" nocase
        $domain31 = "game.vietnamflash.com" nocase
        $domain32 = "hello.bluesky1234.com" nocase
        $domain33 = "hotcup.pw" nocase
        $domain34 = "ipad.vnptnet.info" nocase
        $domain35 = "ks.manlish.net" nocase
        $domain36 = "lepad.fushing.org" nocase
        $domain37 = "lllyyy.adsoft.name" nocase
        $domain38 = "longvn.net" nocase
        $domain39 = "lucky.manlish.net" nocase
        $domain40 = "ma550.adsoft.name" nocase
        $domain41 = "ma550.softad.net" nocase
        $domain42 = "mail.comnnet.net" nocase
        $domain43 = "mail.tiger1234.com" nocase
        $domain44 = "mail.vdcvn.com" nocase
        $domain45 = "manlish.net" nocase
        $domain46 = "mass.longvn.net" nocase
        $domain47 = "mcafee.bluesky1234.com" nocase
        $domain48 = "media.vietnamflash.com" nocase
        $domain49 = "mil.dungk.com" nocase
        $domain50 = "mil.zdungk.com" nocase
        $domain51 = "missyou.longvn.net" nocase
        $domain52 = "mmchj2.telorg.net" nocase
        $domain53 = "mmslsh.tiger1234.com" nocase
        $domain54 = "mobile.vdcvn.com" nocase
        $domain55 = "moit.longvn.net" nocase
        $domain56 = "movie.vdcvn.com" nocase
        $domain57 = "neverdropd.com" nocase
        $domain58 = "news.philstar2.com" nocase
        $domain59 = "news.welikejack.com" nocase
        $domain60 = "npt.vnptnet.info" nocase
        $domain61 = "ns.fushing.org" nocase
        $domain62 = "nycl.neverdropd.com" nocase
        $domain63 = "phcl.followag.org" nocase
        $domain64 = "phcl.neverdropd.com" nocase
        $domain65 = "philstar2.com" nocase
        $domain66 = "phung123.com" nocase
        $domain67 = "pna.adsoft.name" nocase
        $domain68 = "pnavy3.neverdropd.com" nocase
        $domain69 = "satunusa.org" nocase
        $domain70 = "sky.bush2015.net" nocase
        $domain71 = "sky.vietnamflash.com" nocase
        $domain72 = "soap.free.cloudns.asia" nocase
        $domain73 = "softad.net" nocase
        $domain74 = "tcv.tiger1234.com" nocase
        $domain75 = "telecom.longvn.net" nocase
        $domain76 = "telecom.manlish.net" nocase
        $domain77 = "telorg.net" nocase
        $domain78 = "test.facebookmap.top" nocase
        $domain79 = "th-y3.adsoft.name" nocase
        $domain80 = "th550.adsoft.name" nocase
        $domain81 = "th550.softad.net" nocase
        $domain82 = "three.welikejack.com" nocase
        $domain83 = "thy3.softad.net" nocase
        $domain84 = "tiger1234.com" nocase
        $domain85 = "trend.welikejack.com" nocase
        $domain86 = "vdcvn.com" nocase
        $domain87 = "video.philstar2.com" nocase
        $domain88 = "viet.vnptnet.info" nocase
        $domain89 = "viet.zdungk.com" nocase
        $domain90 = "vietnam.vnptnet.info" nocase
        $domain91 = "vietnamflash.com" nocase
        $domain92 = "vnet.fushing.org" nocase
        $domain93 = "vnn.bush2015.net" nocase
        $domain94 = "vnn.phung123.com" nocase
        $domain95 = "vnptnet.info" nocase
        $domain96 = "webmail.philstar2.com" nocase
        $domain97 = "welikejack.com" nocase
        $domain98 = "yok.fushing.org" nocase
        $domain99 = "yote.dellyou.com" nocase
        $ip100 = "64.27.4.157"
        $ip101 = "64.27.4.157"
        $ip102 = "67.210.114.99"
        $ip103 = "67.210.114.99"

    condition:
        any of them
}

rule APT_APPIN {
    meta:
        description = "Indicators associated with APT APPIN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "whiteelephant"

    strings:
        $domain0 = "abdupdates.com" nocase
        $domain1 = "alr3ady.net" nocase
        $domain2 = "antivirusreviewratings.com" nocase
        $domain3 = "authorisedsecurehost.com" nocase
        $domain4 = "bksrv3r001.com" nocase
        $domain5 = "bluecreams.com" nocase
        $domain6 = "bookshopmarket.com" nocase
        $domain7 = "brandsons.net" nocase
        $domain8 = "braninfall.net" nocase
        $domain9 = "c00lh0sting.com" nocase
        $domain10 = "c0ttenc0unty.com" nocase
        $domain11 = "cr3ator01.net" nocase
        $domain12 = "crowcatcher.com" nocase
        $domain13 = "crvhostia.net" nocase
        $domain14 = "currentnewsstore.com" nocase
        $domain15 = "customauthentication.com" nocase
        $domain16 = "devinmartin.net" nocase
        $domain17 = "directsupp0rt.com" nocase
        $domain18 = "divinepower.info" nocase
        $domain19 = "draganheart.com" nocase
        $domain20 = "easyhost-ing.com" nocase
        $domain21 = "easyslidesharing.net" nocase
        $domain22 = "f00dlover.info" nocase
        $domain23 = "filetrusty.net" nocase
        $domain24 = "follow-ship.com" nocase
        $domain25 = "forest-fire.net" nocase
        $domain26 = "foxypredators.com" nocase
        $domain27 = "freensecurehost.com" nocase
        $domain28 = "freesecurehostings.com" nocase
        $domain29 = "freewebdomainhost.com" nocase
        $domain30 = "freewebuserhost.com" nocase
        $domain31 = "gauzpie.com" nocase
        $domain32 = "gmail-loginchk.freehostia.com" nocase
        $domain33 = "h3helnsupp0ort.com" nocase
        $domain34 = "hatemewhy.com" nocase
        $domain35 = "hostingserveronline.net" nocase
        $domain36 = "hotmasalanewssite.com" nocase
        $domain37 = "islam-jindabad.blogspot.com" nocase
        $domain38 = "jasminjorden.com" nocase
        $domain39 = "karzontheway.com" nocase
        $domain40 = "kungfu-panda.info" nocase
        $domain41 = "matrixnotloaded.com" nocase
        $domain42 = "msfileshare.net" nocase
        $domain43 = "msoftweb.com" nocase
        $domain44 = "myt3mple.com" nocase
        $domain45 = "newamazingfacts.com" nocase
        $domain46 = "nitr0rac3.com" nocase
        $domain47 = "pc-technsupport.com" nocase
        $domain48 = "piegauz.net" nocase
        $domain49 = "r3gistration.net" nocase
        $domain50 = "reliablensecurehost.net" nocase
        $domain51 = "s0pp0rtdesk.com" nocase
        $domain52 = "s3rv1c3s.net" nocase
        $domain53 = "secuina.net" nocase
        $domain54 = "securenhost.com" nocase
        $domain55 = "server003.com" nocase
        $domain56 = "server006.com" nocase
        $domain57 = "serverrr.com" nocase
        $domain58 = "serviceaccountloginservicemail.info" nocase
        $domain59 = "servicesaccount.com" nocase
        $domain60 = "sliderocket.com" nocase
        $domain61 = "speedaccelator.com" nocase
        $domain62 = "spidercom.info" nocase
        $domain63 = "t3rmin3.com" nocase
        $domain64 = "taraanasongs.com" nocase
        $domain65 = "thedailynewsheadline.com" nocase
        $domain66 = "tow3r.info" nocase
        $domain67 = "updatemypc.net" nocase
        $domain68 = "updatesl1nk.com" nocase
        $domain69 = "vall3y.com" nocase
        $domain70 = "wearwellgarments.eu" nocase
        $domain71 = "webjavaupdate.com" nocase
        $domain72 = "webmicrosoftupdate.net" nocase
        $ip73 = "212.72.189.74"
        $ip74 = "212.72.189.74"
        $ip75 = "64.186.132.165"
        $ip76 = "65.75.243.251"
        $ip77 = "65.75.243.251"
        $ip78 = "65.75.250.66"
        $ip79 = "65.75.250.66"
        $ip80 = "69.197.147.146"
        $ip81 = "69.197.147.146"
        $ip82 = "75.127.111.165"
        $ip83 = "75.127.111.165"
        $ip84 = "75.127.78.100"
        $ip85 = "75.127.78.100"
        $ip86 = "75.127.91.16"
        $ip87 = "84.243.201.254"
        $ip88 = "84.243.201.254"

    condition:
        any of them
}

rule APT_ARIDVIPER {
    meta:
        description = "Indicators associated with APT ARIDVIPER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "arid gopher, arid viper, spyc23"

    strings:
        $domain0 = "accountforuser.website" nocase
        $domain1 = "acs-group.net" nocase
        $domain2 = "almoshell.website" nocase
        $domain3 = "alwaysgoodidea.com" nocase
        $domain4 = "analyticsandroid.com" nocase
        $domain5 = "angela-bishop.com" nocase
        $domain6 = "anime-con.net" nocase
        $domain7 = "baldwin-gonzalez.live" nocase
        $domain8 = "benyallen.club" nocase
        $domain9 = "chad-jessie.info" nocase
        $domain10 = "chloe-boreman.com" nocase
        $domain11 = "cooperron.me" nocase
        $domain12 = "crashstoreplayer.website" nocase
        $domain13 = "cricket-live.net" nocase
        $domain14 = "criston-cole.com" nocase
        $domain15 = "dabliardogame.com" nocase
        $domain16 = "deangelomcnay.news" nocase
        $domain17 = "delooyp.com" nocase
        $domain18 = "dslam.net" nocase
        $domain19 = "earlahenry.com" nocase
        $domain20 = "elsilvercloud.com" nocase
        $domain21 = "escanor.live" nocase
        $domain22 = "gameservicesplay.com" nocase
        $domain23 = "gmesc.com" nocase
        $domain24 = "godeutalk.com" nocase
        $domain25 = "grace-fraser.site" nocase
        $domain26 = "gsstar.net" nocase
        $domain27 = "haroldramsey.icu" nocase
        $domain28 = "im-inter.net" nocase
        $domain29 = "it-franch-result.info" nocase
        $domain30 = "izocraft.com" nocase
        $domain31 = "jaime-martinez.info" nocase
        $domain32 = "jasondixon.net" nocase
        $domain33 = "jolia-16e7b.appspot.com" nocase
        $domain34 = "judystevenson.info" nocase
        $domain35 = "jumpstartmail.com" nocase
        $domain36 = "katesacker.club" nocase
        $domain37 = "krasil-anthony.icu" nocase
        $domain38 = "labeepuzz.com" nocase
        $domain39 = "leaf-japan.net" nocase
        $domain40 = "lightroom-61eb2.firebaseio.com" nocase
        $domain41 = "london-sport.ne" nocase
        $domain42 = "lrxzklwmzxe.com" nocase
        $domain43 = "luis-dubuque.in" nocase
        $domain44 = "mozelllittel.com" nocase
        $domain45 = "nicoledotson.icu" nocase
        $domain46 = "nortirchats.com" nocase
        $domain47 = "officeappslive.site" nocase
        $domain48 = "orientflags.com" nocase
        $domain49 = "palcivilreg.com" nocase
        $domain50 = "pam-beesly.site" nocase
        $domain51 = "pariberychat.com" nocase
        $domain52 = "paydayloansnew.com" nocase
        $domain53 = "picture-world.info" nocase
        $domain54 = "porthopeminorhockey.net" nocase
        $domain55 = "proj-2bedf.firebaseio.com" nocase
        $domain56 = "proj-54ca0.firebaseio.com" nocase
        $domain57 = "proj-95dae.firebaseio.com" nocase
        $domain58 = "proj3-1e67a.firebaseio.com" nocase
        $domain59 = "project44-5ebbd.firebaseio.com" nocase
        $domain60 = "rashonal.appspot.com" nocase
        $domain61 = "renatchat.com" nocase
        $domain62 = "rnacgroup.com" nocase
        $domain63 = "robert-keegan.life" nocase
        $domain64 = "rviedofree.com" nocase
        $domain65 = "salimafia.net" nocase
        $domain66 = "samwinchester.club" nocase
        $domain67 = "seomoi.net" nocase
        $domain68 = "skippedtestinapp.firebaseio.com" nocase
        $domain69 = "sknzy-mysl.vip" nocase
        $domain70 = "soft-utils.com" nocase
        $domain71 = "sports-et-loisirs.net" nocase
        $domain72 = "storgemydata.website" nocase
        $domain73 = "swsan-lina-soso.info" nocase
        $domain74 = "tatsumifoughtogre.club" nocase
        $domain75 = "tierrastein.live" nocase
        $domain76 = "tophatauc.com" nocase
        $domain77 = "ultraversion.com" nocase
        $domain78 = "yellwo-473d0.appspot.com" nocase
        $domain79 = "zakaria-chotzen.info" nocase
        $ip80 = "213.184.123.144"
        $ip81 = "5.181.23.41"
        $ip82 = "5.181.23.41"
        $ip83 = "91.199.147.84"
        $ip84 = "91.199.147.84"
        $ip85 = "91.219.150.123"

    condition:
        any of them
}

rule APT_ATLASCROSS {
    meta:
        description = "Indicators associated with APT ATLASCROSS"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "activequest.goautodial.com" nocase
        $domain1 = "chat.thedresscodeapp.com" nocase
        $domain2 = "crm.cardabel.com" nocase
        $domain3 = "data.vectorse.com" nocase
        $domain4 = "engage.adaptqe.com" nocase
        $domain5 = "ops-ca.mioying.com" nocase
        $domain6 = "order.staging.photobookworldwide.com" nocase
        $domain7 = "public.pusulait.com" nocase
        $domain8 = "search.allaccountingcareers.com" nocase
        $domain9 = "secure.poliigon.com" nocase
        $domain10 = "superapi-staging.mlmprotec.com" nocase

    condition:
        any of them
}

rule APT_BABYSHARK {
    meta:
        description = "Indicators associated with APT BABYSHARK"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "beastmodser.club" nocase
        $domain1 = "frebough.com" nocase
        $domain2 = "hodbeast.com" nocase
        $domain3 = "retmodul.com" nocase
        $domain4 = "worldinfocontact.club" nocase

    condition:
        any of them
}

rule APT_BADMAGIC {
    meta:
        description = "Indicators associated with APT BADMAGIC"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "01yakutsk.ru" nocase
        $domain1 = "asteriskx.ru" nocase
        $domain2 = "astita.ru" nocase
        $domain3 = "autotimesvc.com" nocase
        $domain4 = "clodmail.ru" nocase
        $domain5 = "contileservices.net" nocase
        $domain6 = "ivanovee.ru" nocase
        $domain7 = "kassperskylaw.ru" nocase
        $domain8 = "kb6ns.ru" nocase
        $domain9 = "licensecheckout.net" nocase
        $domain10 = "mail.01yakutsk.ru" nocase
        $domain11 = "mail.russexportlogistics.ru" nocase
        $domain12 = "passportyandex.net" nocase
        $domain13 = "russexportlogistics.ru" nocase
        $domain14 = "savebrowsing.net" nocase
        $domain15 = "securitysearch.ddns.net" nocase
        $domain16 = "servicehost-update.net" nocase
        $domain17 = "softdownloaderonline.net" nocase
        $domain18 = "statusgeotrust.com" nocase
        $domain19 = "tapiservicemgr.com" nocase
        $domain20 = "uploaderonline.com" nocase
        $domain21 = "uploadingonline.com" nocase
        $domain22 = "versusmain.com" nocase
        $domain23 = "webservice-srv.online" nocase
        $domain24 = "webservice-srv1.online" nocase
        $domain25 = "winupdateronline.com" nocase
        $domain26 = "winuptodate.com" nocase
        $ip27 = "185.166.217.184"
        $ip28 = "5.35.100.31"

    condition:
        any of them
}

rule APT_BAHAMUT {
    meta:
        description = "Indicators associated with APT BAHAMUT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "32e6dwbbpg.de" nocase
        $domain1 = "32player.com" nocase
        $domain2 = "5iw68rugwfcir37uj8z3r6rfaxwd8g8cdcfcqw62.de" nocase
        $domain3 = "96r1yh643o.de" nocase
        $domain4 = "account-googie.com" nocase
        $domain5 = "accountvalidate.com" nocase
        $domain6 = "airfitgym.com" nocase
        $domain7 = "ambicluster.com" nocase
        $domain8 = "appswonder.info" nocase
        $domain9 = "aspnet.dyndns.info" nocase
        $domain10 = "aspnet.dyndns.infoassurecom.info" nocase
        $domain11 = "assurecom.info" nocase
        $domain12 = "ay3a9j7pc3.de" nocase
        $domain13 = "bulletinalerts.com" nocase
        $domain14 = "by4mode.com" nocase
        $domain15 = "capsnit.com" nocase
        $domain16 = "cdn-icloud.co" nocase
        $domain17 = "cdn-icloud.cocelebsnightmares.com" nocase
        $domain18 = "cdw1ir0dc9g3dwl5oh1y.de" nocase
        $domain19 = "celebsnightmares.com" nocase
        $domain20 = "citrusquad.com" nocase
        $domain21 = "classmunch.com" nocase
        $domain22 = "cloud-authorize.com" nocase
        $domain23 = "cocahut.com" nocase
        $domain24 = "cocelebsnightmares.com" nocase
        $domain25 = "cocoka.info" nocase
        $domain26 = "cocoka.infocrawloofle.com" nocase
        $domain27 = "cohealthclubfun.com" nocase
        $domain28 = "crawloofle.com" nocase
        $domain29 = "cyroonline.com" nocase
        $domain30 = "datahost.click" nocase
        $domain31 = "dev-demo.click" nocase
        $domain32 = "devicesupport-rnicrosoft.com" nocase
        $domain33 = "docreader.icu" nocase
        $domain34 = "doctor-reader.icu" nocase
        $domain35 = "domforworld.com" nocase
        $domain36 = "dservices.space" nocase
        $domain37 = "dsharedservices.xyz" nocase
        $domain38 = "electrobric.com" nocase
        $domain39 = "everification-session-load.com" nocase
        $domain40 = "fastfiterzone.com" nocase
        $domain41 = "fjasfjfas89e.gkcx6ye4t4zafw8ju2xdr5na5.de" nocase
        $domain42 = "flux2key.com" nocase
        $domain43 = "freepunjab2020.info" nocase
        $domain44 = "freesexvideos.ch" nocase
        $domain45 = "frexinq.com" nocase
        $domain46 = "ft8hua063okwfdcu21pw.de" nocase
        $domain47 = "fvbyavgyea.com" nocase
        $domain48 = "gateway-yahoo.com" nocase
        $domain49 = "ghelp.co" nocase
        $domain50 = "ghelp.cohealthclubfun.com" nocase
        $domain51 = "gkcx6ye4t4zafw8ju2xdr5na5.de" nocase
        $domain52 = "h94xnghlldx6a862moj3.de" nocase
        $domain53 = "hbx5adg6vk.de" nocase
        $domain54 = "healthclubfun.com" nocase
        $domain55 = "hiltrox.com" nocase
        $domain56 = "hypforever.com" nocase
        $domain57 = "hytechmart.com" nocase
        $domain58 = "i3mode.com" nocase
        $domain59 = "ie-settings.com" nocase
        $domain60 = "imging.site" nocase
        $domain61 = "imging.siteinlineirnage.com" nocase
        $domain62 = "iminglechat.de" nocase
        $domain63 = "infoassurecom.info" nocase
        $domain64 = "infocrawloofle.com" nocase
        $domain65 = "inlineirnage.com" nocase
        $domain66 = "ios-certificate-update.com" nocase
        $domain67 = "ios-update-whatsapp.com" nocase
        $domain68 = "jkiohreh.com" nocase
        $domain69 = "justsikhthings.com" nocase
        $domain70 = "kannat.ns01.us" nocase
        $domain71 = "kannat.ns01.uskhalistanlehar.com" nocase
        $domain72 = "khalistanlehar.com" nocase
        $domain73 = "khalsaforum.com" nocase
        $domain74 = "leastinfo.com" nocase
        $domain75 = "leelee.dnset.com" nocase
        $domain76 = "lepze.com" nocase
        $domain77 = "lizacorner.com" nocase
        $domain78 = "lobertica.info" nocase
        $domain79 = "login-private.com" nocase
        $domain80 = "logon-info-gsupport.com" nocase
        $domain81 = "logstrick.com" nocase
        $domain82 = "m0-rnaiil-siina-chn-reload.everification-session-load.com" nocase
        $domain83 = "mail-incc.com" nocase
        $domain84 = "mail-king.com" nocase
        $domain85 = "mail-validation.info" nocase
        $domain86 = "mail.techsprouts.com" nocase
        $domain87 = "mailinfo-bh.com" nocase
        $domain88 = "mamoonchat.com" nocase
        $domain89 = "marketing-bmut.icu" nocase
        $domain90 = "me-yahoo.com" nocase
        $domain91 = "medieczema.com" nocase
        $domain92 = "memoadvicr.com" nocase
        $domain93 = "metclix.com" nocase
        $domain94 = "middleeastleaks.com" nocase
        $domain95 = "mideastleaks.com" nocase
        $domain96 = "mindcraftstore.com" nocase
        $domain97 = "musicbandfiles.com" nocase
        $domain98 = "myaccount-googie.com" nocase
        $domain99 = "myappie.comyfoodzone.net" nocase
        $ip100 = "134.255.231.233"
        $ip101 = "14.16.88.35"
        $ip102 = "162.55.103.211"
        $ip103 = "162.55.103.211"
        $ip104 = "162.55.103.211"
        $ip105 = "162.55.103.212"
        $ip106 = "162.55.103.212"
        $ip107 = "162.55.103.212"
        $ip108 = "172.64.168.30"
        $ip109 = "172.64.168.30"
        $ip110 = "193.23.161.164"
        $ip111 = "194.156.88.235"
        $ip112 = "45.156.84.129"
        $ip113 = "45.156.85.161"

    condition:
        any of them
}

rule APT_BANISHEDKITTEN {
    meta:
        description = "Indicators associated with APT BANISHEDKITTEN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "aa22-264a, homeland justice, karma"

    strings:
        $domain0 = "screenai.online" nocase

    condition:
        any of them
}

rule APT_BARIUM {
    meta:
        description = "Indicators associated with APT BARIUM"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "shadowhammer, shadowpad, apt41"

    strings:
        $domain0 = "111111.note.down-flash.com" nocase
        $domain1 = "2f2640fb.dns.1433.eu.org" nocase
        $domain2 = "335b5282.dns.1433.eu.org" nocase
        $domain3 = "360photo.oss-cn-hongkong.aliyuncs.com" nocase
        $domain4 = "64-176-59-232.ipv4.staticdns3.io" nocase
        $domain5 = "64.176.35.214.sslip.io" nocase
        $domain6 = "64.176.65.49.sslip.io" nocase
        $domain7 = "6ed123bf7c014f8597b97c1e88c9d7e1.ddns.gcloud.gg" nocase
        $domain8 = "7f4d5b4d9b3b4474a46824c3ae43d06a.ddns.gcloud.gg" nocase
        $domain9 = "91newai.com" nocase
        $domain10 = "a.linuxupdate.info" nocase
        $domain11 = "accounts.longmusic.com" nocase
        $domain12 = "ad.scgawj.com" nocase
        $domain13 = "admin.netbill.pk" nocase
        $domain14 = "adobe-cdn.org" nocase
        $domain15 = "aejava.ddns.net" nocase
        $domain16 = "aejva.ddns.net" nocase
        $domain17 = "afdentry.workstation.eu.org" nocase
        $domain18 = "afsder.com" nocase
        $domain19 = "agegamepay.com" nocase
        $domain20 = "ageofwuxia.com" nocase
        $domain21 = "ageofwuxia.info" nocase
        $domain22 = "ageofwuxia.net" nocase
        $domain23 = "ageofwuxia.org" nocase
        $domain24 = "akacur.tk" nocase
        $domain25 = "akamaixed.net" nocase
        $domain26 = "alibaba.zzux.com" nocase
        $domain27 = "aliyun.com.co" nocase
        $domain28 = "alpha-els.com" nocase
        $domain29 = "alxc.tbtianyan.com" nocase
        $domain30 = "amazonlivenews.com" nocase
        $domain31 = "ampolice.org" nocase
        $domain32 = "andropwn.xyz" nocase
        $domain33 = "aone.ddns.net" nocase
        $domain34 = "ap.philancourts.com" nocase
        $domain35 = "api-v2.cloud" nocase
        $domain36 = "api.emazemedia.com" nocase
        $domain37 = "api.googleauthenticatoronline.com" nocase
        $domain38 = "api.sourcedata.kuwannba.com" nocase
        $domain39 = "app.kaspersky-scan.com" nocase
        $domain40 = "app.microsoftstaticapi.com" nocase
        $domain41 = "app30.hema129.com" nocase
        $domain42 = "app40.hema129.com" nocase
        $domain43 = "arestc.net" nocase
        $domain44 = "asdasw21.icu" nocase
        $domain45 = "ashcrack.freetcp.com" nocase
        $domain46 = "assistcustody.xyz" nocase
        $domain47 = "astudycarsceu.net" nocase
        $domain48 = "asushotfix.com" nocase
        $domain49 = "atomiclampco.com" nocase
        $domain50 = "auth.microsoftsservice.com" nocase
        $domain51 = "az.performed12.com" nocase
        $domain52 = "back.rooter.tk" nocase
        $domain53 = "backdoor.apt.photo" nocase
        $domain54 = "bganmcza.top" nocase
        $domain55 = "bigflx.net" nocase
        $domain56 = "bingsearches.com" nocase
        $domain57 = "bobs8.oss-cn-hongkong.aliyuncs.com" nocase
        $domain58 = "bold-hamilton.207-246-119-197.plesk.page" nocase
        $domain59 = "boopainc.com" nocase
        $domain60 = "box.xxe.pw" nocase
        $domain61 = "browser-events-data-microsoft.com" nocase
        $domain62 = "bssllxqxqzyo.giize.com" nocase
        $domain63 = "bugcheck.xigncodeservice.com" nocase
        $domain64 = "buildhosting.club" nocase
        $domain65 = "bulkyservice.info" nocase
        $domain66 = "byeserver.com" nocase
        $domain67 = "c.ymvh8w5.xyz" nocase
        $domain68 = "caba.superdasqe.me" nocase
        $domain69 = "cargobussi.org" nocase
        $domain70 = "carruthersfredericklawyers.com" nocase
        $domain71 = "carruthersfredericklegals.com" nocase
        $domain72 = "cashmicrosoft.com" nocase
        $domain73 = "cdn.google-au.ga" nocase
        $domain74 = "cdn.ns.time12.cf" nocase
        $domain75 = "cdn.withrental.com" nocase
        $domain76 = "cdn7854.workers.dev" nocase
        $domain77 = "chaindefend.bid" nocase
        $domain78 = "channels.openvista.ma" nocase
        $domain79 = "checkin.travelsanignacio.com" nocase
        $domain80 = "chrome.down-flash.com" nocase
        $domain81 = "chtq.net" nocase
        $domain82 = "closeby.coupons" nocase
        $domain83 = "cloud.kaspersky-scan.com" nocase
        $domain84 = "cloud.microsoftsservice.com" nocase
        $domain85 = "cloud.msapp.workers.dev" nocase
        $domain86 = "cloudat.ddns.net" nocase
        $domain87 = "cloudcat.ddns.net" nocase
        $domain88 = "cnt9.stayout.life" nocase
        $domain89 = "colunm.tk" nocase
        $domain90 = "commandidate.directory" nocase
        $domain91 = "cooltours.s3.sa-east-1.amazonaws.com" nocase
        $domain92 = "copilot-cloud.net" nocase
        $domain93 = "cs.colunm.tk" nocase
        $domain94 = "cs16.dns04.com" nocase
        $domain95 = "cyberkaspersky.com" nocase
        $domain96 = "czs.superdasqe.me" nocase
        $domain97 = "d5922235.dns.1433.eu.org" nocase
        $domain98 = "dasdasgoogle.com" nocase
        $domain99 = "dash.tcplog.com" nocase
        $ip100 = "1.12.224.214"
        $ip101 = "1.92.101.250"
        $ip102 = "1.92.101.250"
        $ip103 = "1.92.101.250"
        $ip104 = "1.92.101.250"
        $ip105 = "1.92.101.250"
        $ip106 = "1.92.101.250"
        $ip107 = "1.92.101.250"
        $ip108 = "1.92.101.250"
        $ip109 = "1.92.107.96"
        $ip110 = "1.92.107.96"
        $ip111 = "1.92.107.96"
        $ip112 = "1.92.107.96"
        $ip113 = "1.92.107.96"
        $ip114 = "1.92.107.96"
        $ip115 = "1.92.107.96"
        $ip116 = "1.92.107.96"
        $ip117 = "1.92.148.235"
        $ip118 = "1.92.148.235"
        $ip119 = "1.92.148.235"
        $ip120 = "1.92.148.235"
        $ip121 = "1.92.148.235"
        $ip122 = "1.92.148.235"
        $ip123 = "1.92.148.235"
        $ip124 = "1.92.148.235"
        $ip125 = "1.92.72.199"
        $ip126 = "1.92.72.199"
        $ip127 = "1.92.72.199"
        $ip128 = "1.92.72.199"
        $ip129 = "1.92.72.199"
        $ip130 = "1.92.72.199"
        $ip131 = "1.92.72.199"
        $ip132 = "1.92.72.199"
        $ip133 = "1.92.75.200"
        $ip134 = "1.92.75.200"
        $ip135 = "1.92.75.200"
        $ip136 = "1.92.75.200"
        $ip137 = "1.92.75.200"
        $ip138 = "1.92.75.200"
        $ip139 = "1.92.75.200"
        $ip140 = "1.92.75.200"
        $ip141 = "1.92.91.219"
        $ip142 = "1.92.91.219"
        $ip143 = "1.92.91.219"
        $ip144 = "1.92.91.219"
        $ip145 = "1.92.91.219"
        $ip146 = "1.92.91.219"
        $ip147 = "1.92.91.219"
        $ip148 = "1.92.91.219"
        $ip149 = "1.92.98.22"

    condition:
        any of them
}

rule APT_BATSHADOW {
    meta:
        description = "Indicators associated with APT BATSHADOW"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "vampirebot"

    strings:
        $domain0 = "api.samsungcareers.work" nocase
        $domain1 = "api3.samsungcareers.work" nocase
        $domain2 = "djactuallsbuilds.com" nocase
        $domain3 = "ftp.spaceq.ovh" nocase
        $domain4 = "get-reponse-subt1.duckdns.org" nocase
        $domain5 = "get-reponse-subt2.duckdns.org" nocase
        $domain6 = "get-reponse-subt3.duckdns.org" nocase
        $domain7 = "get-reponse-subt4.duckdns.org" nocase
        $domain8 = "img.samsungcareers.work" nocase
        $domain9 = "jobs-infomarriott.com" nocase
        $domain10 = "jobs-marriott.com" nocase
        $domain11 = "jobswork.vn" nocase
        $domain12 = "mail.jobs-infomarriott.com" nocase
        $domain13 = "mail.jobs-marriott.com" nocase
        $domain14 = "mail.jobswork.vn" nocase
        $domain15 = "mysupportnetflix.com" nocase
        $domain16 = "panel2.samsungcareers.work" nocase
        $domain17 = "samsung-work.com" nocase
        $domain18 = "samsungcareers.work" nocase
        $domain19 = "spaceq.ovh" nocase
        $domain20 = "workjobs.net" nocase
        $ip21 = "5.252.235.172"

    condition:
        any of them
}

rule APT_BISONAL {
    meta:
        description = "Indicators associated with APT BISONAL"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "bisonal, tonto, tontoteam"

    strings:
        $domain0 = "0906.toh.info" nocase
        $domain1 = "21kmg.my-homeip.net" nocase
        $domain2 = "abulasha-banama.onedumb.com" nocase
        $domain3 = "acivo.serveblog.net" nocase
        $domain4 = "adobe-online.com" nocase
        $domain5 = "adoberevise.com" nocase
        $domain6 = "adobeupdata.zzux.com" nocase
        $domain7 = "adobeupdate.dns04.com" nocase
        $domain8 = "agent.my-homeip.net" nocase
        $domain9 = "alleyk.onthewifi.com" nocase
        $domain10 = "amanser951.otzo.com" nocase
        $domain11 = "anna111.epac.to" nocase
        $domain12 = "anrnet.servegame.com" nocase
        $domain13 = "applejp.myfw.us" nocase
        $domain14 = "asheepa.sytes.net" nocase
        $domain15 = "attachdaum.servecounterstrike.com" nocase
        $domain16 = "attachmaildaum.serveblog.net" nocase
        $domain17 = "attachmaildaum.servecounterstrike.com" nocase
        $domain18 = "babyhome.lflink.com" nocase
        $domain19 = "babyhome.mefound.com" nocase
        $domain20 = "baekmaonline.com" nocase
        $domain21 = "bbc.xxxy.info" nocase
        $domain22 = "beatidc.com" nocase
        $domain23 = "best.indoingwulearn.com" nocase
        $domain24 = "bitsshare.com" nocase
        $domain25 = "bizmeka.viewdns.net" nocase
        $domain26 = "bluecat.mefound.com" nocase
        $domain27 = "bluesky.jkub.com" nocase
        $domain28 = "bravojack.justdied.com" nocase
        $domain29 = "bucketnec.bounceme.net" nocase
        $domain30 = "chrgeom.system-ns.net" nocase
        $domain31 = "chromeupdate.lflink.com" nocase
        $domain32 = "chsoun.serveftp.com" nocase
        $domain33 = "ckstar.zapto.org" nocase
        $domain34 = "cnnmirror.com" nocase
        $domain35 = "comunity.system-ns.org" nocase
        $domain36 = "connts.zzux.com" nocase
        $domain37 = "creepbeforeyouwalk.com" nocase
        $domain38 = "daecheol.myvnc.com" nocase
        $domain39 = "daum.xxuz.com" nocase
        $domain40 = "daummail.otzo.com" nocase
        $domain41 = "dds.walshdavis.com" nocase
        $domain42 = "developman.ocry.com" nocase
        $domain43 = "dnsdns1.passas.us" nocase
        $domain44 = "doctor-s.dhcp.biz" nocase
        $domain45 = "doctor-s.edns.biz" nocase
        $domain46 = "eburim.viewdns.net" nocase
        $domain47 = "eduin21.zapto.org" nocase
        $domain48 = "elecinfonec.servehalflife.com" nocase
        $domain49 = "emsit.serveirc.com" nocase
        $domain50 = "etude.servemp3.com" nocase
        $domain51 = "euiro8966.organiccrap.com" nocase
        $domain52 = "facegooglebook.mrbasic.com" nocase
        $domain53 = "faceto.uglyas.com" nocase
        $domain54 = "fdods.my03.com" nocase
        $domain55 = "fdtg.dynamic-dns.net" nocase
        $domain56 = "finance.my-homeip.com" nocase
        $domain57 = "finance.my-homeip.net" nocase
        $domain58 = "foodlab.hopto.org" nocase
        $domain59 = "formsgle.freedynamicdns.net" nocase
        $domain60 = "formsgle.freedynamicdns.org" nocase
        $domain61 = "fose.mos2ioa.com" nocase
        $domain62 = "free2015.longmusic.com" nocase
        $domain63 = "freemusic.zzux.com" nocase
        $domain64 = "fresh.servepics.com" nocase
        $domain65 = "ftp.sshdd.toythieves.com" nocase
        $domain66 = "g00gleru.wikaba.com" nocase
        $domain67 = "games.my-homeip.com" nocase
        $domain68 = "gedadye.com" nocase
        $domain69 = "global.freedynamicdns.net" nocase
        $domain70 = "global.freedynamicdns.org" nocase
        $domain71 = "gmailserverweb.com" nocase
        $domain72 = "gmarket.system-ns.org" nocase
        $domain73 = "golfmsdn.com" nocase
        $domain74 = "gomalove.system-ns.org" nocase
        $domain75 = "gotomail.ddns.net" nocase
        $domain76 = "gtfd.mos2ioa.com" nocase
        $domain77 = "hairouni.serveblog.net" nocase
        $domain78 = "hamonsoft.serveblog.net" nocase
        $domain79 = "hanseo1.hopto.org" nocase
        $domain80 = "hansun.serveblog.net" nocase
        $domain81 = "harvest.my-homeip.net" nocase
        $domain82 = "havsar.com" nocase
        $domain83 = "hellomydog.compress.to" nocase
        $domain84 = "hellomydog.mrface.com" nocase
        $domain85 = "home-blog.dynssl.com" nocase
        $domain86 = "hometax.onthewifi.com" nocase
        $domain87 = "hosting.tempors.com" nocase
        $domain88 = "hotadobes.com" nocase
        $domain89 = "hwarang.myddns.me" nocase
        $domain90 = "imbc.onthewifi.com" nocase
        $domain91 = "indbaba.myfw.us" nocase
        $domain92 = "indoingwulearn.com" nocase
        $domain93 = "instructor.giize.com" nocase
        $domain94 = "jaminss.viewdns.net" nocase
        $domain95 = "janara.freedynamicdns.org" nocase
        $domain96 = "japanbaba.myfw.us" nocase
        $domain97 = "jennifer998.lookin.at" nocase
        $domain98 = "jeoash.servemp3.com" nocase
        $domain99 = "jobnate.system-ns.org" nocase
        $ip100 = "103.231.14.134"
        $ip101 = "103.85.20.194"
        $ip102 = "137.220.176.165"
        $ip103 = "153.234.77.155"
        $ip104 = "45.133.194.135"

    condition:
        any of them
}

rule APT_BITTER {
    meta:
        description = "Indicators associated with APT BITTER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-08, apt-q-37, apt-q-41"

    strings:
        $domain0 = "1drivestorage.com" nocase
        $domain1 = "365cloudz.esanojinjasvc.com" nocase
        $domain2 = "55five.lol" nocase
        $domain3 = "888toto.com" nocase
        $domain4 = "8toto.co" nocase
        $domain5 = "918slot.top" nocase
        $domain6 = "99media.com.pk" nocase
        $domain7 = "99togel.org" nocase
        $domain8 = "99toto.shop" nocase
        $domain9 = "a.churchill91.com" nocase
        $domain10 = "aadresourcing.com" nocase
        $domain11 = "abelewebconnect.com" nocase
        $domain12 = "activemobistore.ddns.net" nocase
        $domain13 = "adamsresearchshare.com" nocase
        $domain14 = "aday.primeservices.mobi" nocase
        $domain15 = "aduhoki88.com" nocase
        $domain16 = "affinitycapitalgp.com" nocase
        $domain17 = "affinitycapitalgr.com" nocase
        $domain18 = "alfiehealtcareservice.com" nocase
        $domain19 = "alfiehealthcareservice.com" nocase
        $domain20 = "alkhaleejpk.info" nocase
        $domain21 = "alvesbarcelona.com" nocase
        $domain22 = "andbouncersclub.com" nocase
        $domain23 = "andrewswebstorage.com" nocase
        $domain24 = "apifilestore.net" nocase
        $domain25 = "app.chabaka.com" nocase
        $domain26 = "app2.appvlc.com" nocase
        $domain27 = "appbriar.com" nocase
        $domain28 = "appprotonvpn.com" nocase
        $domain29 = "appsupdate.net" nocase
        $domain30 = "archiverst.com" nocase
        $domain31 = "aroundtheworld123.net" nocase
        $domain32 = "ashersoftlib.com" nocase
        $domain33 = "autodefragapp.com" nocase
        $domain34 = "bakuackermannfashions.com" nocase
        $domain35 = "balkanclan.com" nocase
        $domain36 = "bartelemarks.com" nocase
        $domain37 = "benclickstudio.com" nocase
        $domain38 = "bensnewfashionstyles.com" nocase
        $domain39 = "bheragreens.com" nocase
        $domain40 = "bickrickneoservice.com" nocase
        $domain41 = "biocons.pk" nocase
        $domain42 = "blth32serv.net" nocase
        $domain43 = "blucollinsoutien.com" nocase
        $domain44 = "bluelotus.mail-gdrive.com" nocase
        $domain45 = "bootcampquest.com" nocase
        $domain46 = "botanoolifeapp.net" nocase
        $domain47 = "box.livevideosonlinepk.com" nocase
        $domain48 = "bravojacksonmentor.com" nocase
        $domain49 = "briarapppro.org" nocase
        $domain50 = "broadsforthestate.com" nocase
        $domain51 = "bsdqcaptureman.com" nocase
        $domain52 = "btappclientsvc.net" nocase
        $domain53 = "bulltrader.vip" nocase
        $domain54 = "camncryptsvc.net" nocase
        $domain55 = "caravelcruiser.com" nocase
        $domain56 = "care.autodefragapp.com" nocase
        $domain57 = "carlminiclub.com" nocase
        $domain58 = "cbyxhuxo663.ddns.net" nocase
        $domain59 = "ccltdcn.org" nocase
        $domain60 = "cdaxpropsvc.net" nocase
        $domain61 = "chabaka.com" nocase
        $domain62 = "chinatel90.com" nocase
        $domain63 = "churchill91.com" nocase
        $domain64 = "cjcjegb9k5vg46vkns5g.sportsaccessstore.com" nocase
        $domain65 = "clairsvanieclub.com" nocase
        $domain66 = "cloud-storage-service.com" nocase
        $domain67 = "cloudaff.net" nocase
        $domain68 = "coauthcn.com" nocase
        $domain69 = "coerciondigital.com" nocase
        $domain70 = "colorsofnether.com" nocase
        $domain71 = "com-ae.net" nocase
        $domain72 = "commonlifesupport.com" nocase
        $domain73 = "comnmsgwrapsvc.net" nocase
        $domain74 = "confirm97.com" nocase
        $domain75 = "converse-app.org" nocase
        $domain76 = "cpcalendars.tomcruefrshsvc.com" nocase
        $domain77 = "cpcontacts.tomcruefrshsvc.com" nocase
        $domain78 = "createasocialcard.top" nocase
        $domain79 = "crudestopics.com" nocase
        $domain80 = "currweather.com" nocase
        $domain81 = "dappscryp.com" nocase
        $domain82 = "dashonlineclub.com" nocase
        $domain83 = "daveonenewtestpanel.com" nocase
        $domain84 = "deliverymailserver.com" nocase
        $domain85 = "demolaservices.com" nocase
        $domain86 = "deriksystemspartens.com" nocase
        $domain87 = "destiny91.com" nocase
        $domain88 = "devflowservice.com" nocase
        $domain89 = "devqrytoprar.net" nocase
        $domain90 = "diginurworld.com" nocase
        $domain91 = "diyefosterfeeds.com" nocase
        $domain92 = "dnldsalecraze.com" nocase
        $domain93 = "domainnamevalidator.com" nocase
        $domain94 = "domainregistationcheck.com" nocase
        $domain95 = "downloadclouddata.com" nocase
        $domain96 = "dracjohnsupport.com" nocase
        $domain97 = "drogbachelsea.com" nocase
        $domain98 = "dtzappaccount.com" nocase
        $domain99 = "easyiplookup.com" nocase
        $ip100 = "103.57.251.154"
        $ip101 = "107.172.39.100"
        $ip102 = "107.173.63.218"
        $ip103 = "110.42.64.137"
        $ip104 = "134.255.210.127"
        $ip105 = "135.125.242.211"
        $ip106 = "141.94.68.169"
        $ip107 = "147.124.223.140"
        $ip108 = "151.236.14.173"
        $ip109 = "151.236.21.48"
        $ip110 = "151.236.4.164"
        $ip111 = "151.236.9.75"
        $ip112 = "151.236.9.75"
        $ip113 = "158.255.215.45"
        $ip114 = "162.0.216.229"
        $ip115 = "162.0.216.229"
        $ip116 = "162.252.172.67"
        $ip117 = "162.252.175.131"
        $ip118 = "162.252.175.131"
        $ip119 = "163.245.220.108"
        $ip120 = "167.88.15.93"
        $ip121 = "185.106.123.198"
        $ip122 = "185.117.72.87"
        $ip123 = "185.117.73.195"
        $ip124 = "185.117.73.209"
        $ip125 = "185.141.25.244"
        $ip126 = "185.193.48.135"
        $ip127 = "185.193.50.233"
        $ip128 = "185.237.166.24"
        $ip129 = "185.76.79.30"
        $ip130 = "188.214.33.170"
        $ip131 = "192.71.213.128"
        $ip132 = "192.71.249.194"
        $ip133 = "193.142.58.38"
        $ip134 = "193.29.58.210"
        $ip135 = "194.110.246.254"
        $ip136 = "194.71.227.222"
        $ip137 = "209.74.80.194"
        $ip138 = "23.106.122.149"
        $ip139 = "23.254.128.22"
        $ip140 = "45.11.19.170"
        $ip141 = "45.56.165.121"
        $ip142 = "45.66.248.66"
        $ip143 = "45.86.163.212"
        $ip144 = "46.183.186.208"
        $ip145 = "46.183.187.42"
        $ip146 = "46.183.25.24"
        $ip147 = "46.249.38.18"
        $ip148 = "46.249.38.18"
        $ip149 = "46.30.188.43"

    condition:
        any of them
}

rule APT_BLACKGEAR {
    meta:
        description = "Indicators associated with APT BLACKGEAR"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "abcdns.bounceme.net" nocase
        $domain1 = "abcpees.webhop.net" nocase
        $domain2 = "ancelon.webhop.net" nocase
        $domain3 = "anitacxb.servebbs.com" nocase
        $domain4 = "bi-apple.net" nocase
        $domain5 = "bitdefender.minidns.net" nocase
        $domain6 = "ccc.th-fish.com" nocase
        $domain7 = "ccuugo.8866.org" nocase
        $domain8 = "checkerror.obama20009.com" nocase
        $domain9 = "cheng.pc-officer.com" nocase
        $domain10 = "cometocome.8866.org" nocase
        $domain11 = "computerupdate.servegame.com" nocase
        $domain12 = "cooperlzh.liondrive.com" nocase
        $domain13 = "d1c2f3.3322.org" nocase
        $domain14 = "data.lovequintet.com" nocase
        $domain15 = "divineart.dyndns.org" nocase
        $domain16 = "domain.uyghuri.com" nocase
        $domain17 = "enterdia.zyns.com" nocase
        $domain18 = "erbilin.blogdns.com" nocase
        $domain19 = "feng.pc-officer.com" nocase
        $domain20 = "fifaoopp.webhop.net" nocase
        $domain21 = "fisu.rr.nu" nocase
        $domain22 = "gmail.servebbs.com" nocase
        $domain23 = "goodhope.no-ip.org" nocase
        $domain24 = "googleads.serveftp.com" nocase
        $domain25 = "handinhand.blogdns.org" nocase
        $domain26 = "harris.3322.org" nocase
        $domain27 = "hinetrouter.serveftp.org" nocase
        $domain28 = "hongzong.xicp.net" nocase
        $domain29 = "hzcj.8866.org" nocase
        $domain30 = "hzong.welikejack.com" nocase
        $domain31 = "ie-update.sytes.net" nocase
        $domain32 = "ifsbsa.bounceme.net" nocase
        $domain33 = "ihe1979.3322.org" nocase
        $domain34 = "intershare.zapto.net" nocase
        $domain35 = "intershare.zapto.org" nocase
        $domain36 = "introy.toh.info" nocase
        $domain37 = "ius.uyghuri.com" nocase
        $domain38 = "japanisok.selfip.org" nocase
        $domain39 = "jmjm.bounceme.net" nocase
        $domain40 = "killabcd.9966.org" nocase
        $domain41 = "kingcoast.3322.org" nocase
        $domain42 = "kingcoast.6688.org" nocase
        $domain43 = "kingcoast.homedns.org" nocase
        $domain44 = "kmtzh.zyns.com" nocase
        $domain45 = "ksforever.no-ip.org" nocase
        $domain46 = "liumingzhen.myftp.org" nocase
        $domain47 = "liumingzhen.zapto.org" nocase
        $domain48 = "liveupdate.dyndns.biz" nocase
        $domain49 = "lovemoney.2288.org" nocase
        $domain50 = "lycosgame.com" nocase
        $domain51 = "lyle.3322.org" nocase
        $domain52 = "lyle.homedns.org" nocase
        $domain53 = "mcrcancer.podzone.org" nocase
        $domain54 = "mcrcount.bounceme.net" nocase
        $domain55 = "mcrcount.podzone.org" nocase
        $domain56 = "meet.servebbs.org" nocase
        $domain57 = "menberservice.3322.org" nocase
        $domain58 = "microsoft.dumb1.com" nocase
        $domain59 = "mkmk.bounceme.net" nocase
        $domain60 = "mmm.freesite.us" nocase
        $domain61 = "msdndown1.3322.org" nocase
        $domain62 = "myblog.bounceme.net" nocase
        $domain63 = "mylife33.zapto.org" nocase
        $domain64 = "mywebpage.3322.org" nocase
        $domain65 = "newton1666.3322.org" nocase
        $domain66 = "nothingtolose.3322.org" nocase
        $domain67 = "nothingtolose.changeip.org" nocase
        $domain68 = "olyone.com" nocase
        $domain69 = "oohshit.dnsdojo.com" nocase
        $domain70 = "own.webhop.net" nocase
        $domain71 = "oyd.3322.org" nocase
        $domain72 = "pklei45.3322.org" nocase
        $domain73 = "pklei56.3322.org" nocase
        $domain74 = "plscoverko.meibu.com" nocase
        $domain75 = "pop.miyazakihousou.com" nocase
        $domain76 = "popftp.bounceme.net" nocase
        $domain77 = "popo.bi-apple.net" nocase
        $domain78 = "popularcat.hopto.org" nocase
        $domain79 = "pvp.scylla4421.com" nocase
        $domain80 = "rainflow.dontexist.com" nocase
        $domain81 = "readdook.selfip.com" nocase
        $domain82 = "red.istme.com" nocase
        $domain83 = "s27.dondon555.com" nocase
        $domain84 = "sbd.7766.org" nocase
        $domain85 = "sctw06.com" nocase
        $domain86 = "services.dyndns.biz" nocase
        $domain87 = "smtp.hitachis.net" nocase
        $domain88 = "sportsnews.chilichi.com" nocase
        $domain89 = "stemba.bounceme.net" nocase
        $domain90 = "support-microsoft.net" nocase
        $domain91 = "sweetbug.selfip.net" nocase
        $domain92 = "sweetcard.3322.org" nocase
        $domain93 = "sweetseed.3322.org" nocase
        $domain94 = "tempfy.9966.org" nocase
        $domain95 = "tempsys.8866.prg" nocase
        $domain96 = "tencent.ikwb.com" nocase
        $domain97 = "todayzh.sytes.net" nocase
        $domain98 = "tv.kingdomcer.com" nocase
        $domain99 = "update.ddns.ms" nocase

    condition:
        any of them
}

rule APT_BLACKTECH {
    meta:
        description = "Indicators associated with APT BLACKTECH"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "activate.linkblackclover.com" nocase
        $domain1 = "adobeupdate.serveusers.com" nocase
        $domain2 = "amazon.panasocin.com" nocase
        $domain3 = "centos.onthewifi.com" nocase
        $domain4 = "centos1.chinabrands.xyz" nocase
        $domain5 = "centos2.chinabrands.xyz" nocase
        $domain6 = "centosupdate.dynamic-dns.net" nocase
        $domain7 = "centosupdates.com" nocase
        $domain8 = "centrosupdate.proxydns.com" nocase
        $domain9 = "config.zapto.org" nocase
        $domain10 = "csp.fortinetline.com" nocase
        $domain11 = "em.totalpople.info" nocase
        $domain12 = "evergo.dnset.com" nocase
        $domain13 = "fibtec.jkub.com" nocase
        $domain14 = "fortinetline.com" nocase
        $domain15 = "gstrap.jkub.com" nocase
        $domain16 = "harb.bbsindex.com" nocase
        $domain17 = "herace.https443.org" nocase
        $domain18 = "idonotknow.lflinkup.com" nocase
        $domain19 = "idonotknow.lflinkup.net" nocase
        $domain20 = "idonotknow.serveusers.com" nocase
        $domain21 = "inkeslive.com" nocase
        $domain22 = "linuxhome.jkub.com" nocase
        $domain23 = "macfee-update.serveftp.com" nocase
        $domain24 = "microsoftonline.com.authorizeddns.net" nocase
        $domain25 = "microsoftvm.net" nocase
        $domain26 = "ns1001.centosupdates.com" nocase
        $domain27 = "office.panasocin.com" nocase
        $domain28 = "okinawas.ssl443.org" nocase
        $domain29 = "org.misecure.com" nocase
        $domain30 = "panasocin.com" nocase
        $domain31 = "portal.fortinetline.com" nocase
        $domain32 = "portal.microsoftvm.net" nocase
        $domain33 = "redhatstate.hopto.org" nocase
        $domain34 = "rutentw.com" nocase
        $domain35 = "securitycenter.kozow.com" nocase
        $domain36 = "systeminfo.centosupdates.com" nocase
        $domain37 = "totalpople.info" nocase
        $domain38 = "update.centosupdates.com" nocase
        $domain39 = "update.panasocin.com" nocase
        $domain40 = "updates.centosupdates.com" nocase
        $domain41 = "web2008.rutentw.com" nocase
        $domain42 = "wg1.inkeslive.com" nocase
        $domain43 = "woc.yasonbin.info" nocase
        $domain44 = "yasonbin.info" nocase
        $ip45 = "122.116.205.124"
        $ip46 = "172.104.109.217"
        $ip47 = "212.115.54.194"
        $ip48 = "223.200.120.73"
        $ip49 = "61.216.119.56"

    condition:
        any of them
}

rule APT_BLADEDFELINE {
    meta:
        description = "Indicators associated with APT BLADEDFELINE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "laret, pinar"

    strings:
        $ip0 = "178.209.51.61"
        $ip1 = "178.209.51.61"
        $ip2 = "178.209.51.61"
        $ip3 = "185.76.78.177"
        $ip4 = "185.76.78.177"
        $ip5 = "185.76.78.177"

    condition:
        any of them
}

rule APT_BLINDEAGLE {
    meta:
        description = "Indicators associated with APT BLINDEAGLE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "aguilaciega, apt36, apt-c-36"

    strings:
        $domain0 = "ajaxcoder.polycomusa.com" nocase
        $domain1 = "aseguradotelle.duckdns.org" nocase
        $domain2 = "autgerman.autgerman.com" nocase
        $domain3 = "autgerman.com" nocase
        $domain4 = "axu87794.polycomusa.com" nocase
        $domain5 = "ceoempresarialsas.com" nocase
        $domain6 = "ceosas.linkpc.net" nocase
        $domain7 = "ceoseguros.com" nocase
        $domain8 = "chileimportaciones.cl" nocase
        $domain9 = "cryptersandtools.minhacasa.tv" nocase
        $domain10 = "defenderav.con-ip.com" nocase
        $domain11 = "dian.server.tl" nocase
        $domain12 = "diangovcomuiscia.com" nocase
        $domain13 = "edificiobaldeares.linkpc.net" nocase
        $domain14 = "enero2022.con-ip.com" nocase
        $domain15 = "envio02-04.duckdns.org" nocase
        $domain16 = "envio14-03.duckdns.org" nocase
        $domain17 = "envio1414.duckdns.org" nocase
        $domain18 = "envio19-05.duckdns.org" nocase
        $domain19 = "envio21-05.duckdns.org" nocase
        $domain20 = "envio2333.duckdns.org" nocase
        $domain21 = "envio26-03.duckdns.org" nocase
        $domain22 = "envio28-003.duckdns.org" nocase
        $domain23 = "envio29.duckdns.org" nocase
        $domain24 = "envio31-03.duckdns.org" nocase
        $domain25 = "equipo.linkpc.net" nocase
        $domain26 = "febenvi.duckdns.org" nocase
        $domain27 = "giraffebear.polycomusa.com" nocase
        $domain28 = "hellmagers.polycomusa.com" nocase
        $domain29 = "host-rami.polycomusa.com" nocase
        $domain30 = "ismaboli.com" nocase
        $domain31 = "laminascol.linkpc.net" nocase
        $domain32 = "marzo72022.con-ip.com" nocase
        $domain33 = "medicosco.publicvm.com" nocase
        $domain34 = "medicosempresa.com" nocase
        $domain35 = "mega.polycomusa.com" nocase
        $domain36 = "mentes.publicvm.com" nocase
        $domain37 = "ojosostenerfebrero.duckdns.org" nocase
        $domain38 = "perfect5.publicvm.com" nocase
        $domain39 = "perfect8.publicvm.com" nocase
        $domain40 = "polycomusa.com" nocase
        $domain41 = "pub-4c182737706e41d29aee6cc5517f834d.r2.dev" nocase
        $domain42 = "pub-6346c84860d5480393a1799fb277dfdc.r2.dev" nocase
        $domain43 = "qua25q.duckdns.org" nocase
        $domain44 = "qua25qua.duckdns.org" nocase
        $domain45 = "respaldito01.duckdns.org" nocase
        $domain46 = "respaldito03.duckdns.org" nocase
        $domain47 = "respaldomax3.duckdns.org" nocase
        $domain48 = "respaldomax4.duckdns.org" nocase
        $domain49 = "respaldomx1.duckdns.org" nocase
        $domain50 = "respaldomx5.duckdns.org" nocase
        $domain51 = "sainth.polycomusa.com" nocase
        $domain52 = "sanctuary.polycomusa.com" nocase
        $domain53 = "sicariop.polycomusa.com" nocase
        $domain54 = "smakaf1.polycomusa.com" nocase
        $domain55 = "strekhost2066.duckdns.org" nocase
        $domain56 = "subirfact.com" nocase
        $domain57 = "systemwin.linkpc.net" nocase
        $domain58 = "therussian.polycomusa.com" nocase
        $domain59 = "upxsystems.com" nocase
        $domain60 = "vargasvargasabogadosnotificaciones.privat.lc" nocase
        $domain61 = "yty0do.polycomusa.com" nocase
        $domain62 = "zhost.polycomusa.com" nocase
        $domain63 = "zvoracle.polycomusa.com" nocase
        $ip64 = "103.151.124.233"
        $ip65 = "128.90.108.115"
        $ip66 = "128.90.115.167"
        $ip67 = "128.90.115.93"
        $ip68 = "128.90.115.95"
        $ip69 = "128.90.130.185"
        $ip70 = "177.255.89.112"
        $ip71 = "177.255.89.112"
        $ip72 = "181.130.5.112"
        $ip73 = "181.130.9.145"
        $ip74 = "181.130.9.145"
        $ip75 = "181.131.217.174"
        $ip76 = "2.56.57.27"
        $ip77 = "2.56.59.208"
        $ip78 = "35.34.5.27"
        $ip79 = "45.147.231.85"
        $ip80 = "62.197.136.252"
        $ip81 = "69.167.10.207"
        $ip82 = "69.167.11.9"
        $ip83 = "69.167.8.118"

    condition:
        any of them
}

rule APT_BLOODYWOLF {
    meta:
        description = "Indicators associated with APT BLOODYWOLF"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "ach-uz.com" nocase
        $domain1 = "audit-kg.com" nocase
        $domain2 = "esf-kg.com" nocase
        $domain3 = "hgame33.com" nocase
        $domain4 = "hisobot-uz.com" nocase
        $domain5 = "minjust-kg.com" nocase
        $domain6 = "nac-ac.com" nocase
        $domain7 = "ravinads.com" nocase
        $domain8 = "soliq-uz.com" nocase
        $domain9 = "ttbbaits.com" nocase
        $domain10 = "uzaudit.com" nocase

    condition:
        any of them
}

rule APT_BLUENOROFF {
    meta:
        description = "Indicators associated with APT BLUENOROFF"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "cageychameleon, cryptocore, cryptomimic"

    strings:
        $domain0 = "02euweb.us" nocase
        $domain1 = "02io.us" nocase
        $domain2 = "02room.us" nocase
        $domain3 = "02us.sbs" nocase
        $domain4 = "02usweb.sbs" nocase
        $domain5 = "02usweb.us" nocase
        $domain6 = "02web-zoom.us" nocase
        $domain7 = "02web.sbs" nocase
        $domain8 = "02web.zoom.02webus.sbs" nocase
        $domain9 = "02webus.sbs" nocase
        $domain10 = "02webus.zoom.02us.sbs" nocase
        $domain11 = "02webus.zoom.web02.sbs" nocase
        $domain12 = "02webzoom.us" nocase
        $domain13 = "03app.live" nocase
        $domain14 = "03app.sbs" nocase
        $domain15 = "04web.sbs" nocase
        $domain16 = "05ie.live" nocase
        $domain17 = "05in.one" nocase
        $domain18 = "05live.biz" nocase
        $domain19 = "05live.co" nocase
        $domain20 = "05live.live" nocase
        $domain21 = "05live.sbs" nocase
        $domain22 = "05live.xyz" nocase
        $domain23 = "05meet.am.in" nocase
        $domain24 = "05meet.click" nocase
        $domain25 = "05meet.co" nocase
        $domain26 = "05meet.live" nocase
        $domain27 = "05meet.sbs" nocase
        $domain28 = "05meet.us" nocase
        $domain29 = "05meetus.web05.uk" nocase
        $domain30 = "05uk.us" nocase
        $domain31 = "05ukweb.uk" nocase
        $domain32 = "05us.live" nocase
        $domain33 = "05us.sbs" nocase
        $domain34 = "05us.zoom.05webus.sbs" nocase
        $domain35 = "05us.zoom.web05.sbs" nocase
        $domain36 = "05usweb.us" nocase
        $domain37 = "05usweb.zoom.meet-05.sbs" nocase
        $domain38 = "05web.us" nocase
        $domain39 = "05webus.meet.05uk.us" nocase
        $domain40 = "05webus.sbs" nocase
        $domain41 = "06eu.us" nocase
        $domain42 = "06in.us" nocase
        $domain43 = "06ln.live" nocase
        $domain44 = "06on.us" nocase
        $domain45 = "06ukweb.uk" nocase
        $domain46 = "06us.live" nocase
        $domain47 = "06us.sbs" nocase
        $domain48 = "06us.us" nocase
        $domain49 = "06us.zoom.web06.eu" nocase
        $domain50 = "06us.zoom.web06.sbs" nocase
        $domain51 = "06usweb.us" nocase
        $domain52 = "06usweb.zoom.us06.sbs" nocase
        $domain53 = "06web.us06.in" nocase
        $domain54 = "06web.zoomconnect.io" nocase
        $domain55 = "06web.zoomlink.studio" nocase
        $domain56 = "06webin.us" nocase
        $domain57 = "07-web.us" nocase
        $domain58 = "07usweb.site" nocase
        $domain59 = "07web.zoom.uk07.pro" nocase
        $domain60 = "07webus.zoom.us07.sbs" nocase
        $domain61 = "163qiye.top" nocase
        $domain62 = "1driv.org" nocase
        $domain63 = "1drv.email" nocase
        $domain64 = "1drvmail.work" nocase
        $domain65 = "1ives.co" nocase
        $domain66 = "256ventures.us" nocase
        $domain67 = "31ventures.info" nocase
        $domain68 = "32.ww-live.online" nocase
        $domain69 = "3f.teams-meet.xyz" nocase
        $domain70 = "5q.ms-meets.online" nocase
        $domain71 = "a.mylkc.cloudns.ch" nocase
        $domain72 = "abf-cap.co" nocase
        $domain73 = "abf-cap.com" nocase
        $domain74 = "abiesvc.com" nocase
        $domain75 = "abiesvc.info" nocase
        $domain76 = "abiesvc.jp.net" nocase
        $domain77 = "account-googlemeet.com" nocase
        $domain78 = "addressstore.space" nocase
        $domain79 = "adiclas-nft.quest" nocase
        $domain80 = "admin.unitpowergeneration.top" nocase
        $domain81 = "adteam.am.in" nocase
        $domain82 = "ai02n.sbs" nocase
        $domain83 = "aidpartners.org" nocase
        $domain84 = "ain01.sbs" nocase
        $domain85 = "ajayplamingo.com" nocase
        $domain86 = "aleslosev.workers.dev" nocase
        $domain87 = "algozzoom.us006web.us" nocase
        $domain88 = "altair-vc.co.uk" nocase
        $domain89 = "altair-vc.com" nocase
        $domain90 = "altair.linkpc.net" nocase
        $domain91 = "amazonaws1.info" nocase
        $domain92 = "amzonnews.club" nocase
        $domain93 = "analysis.arkinvst.com" nocase
        $domain94 = "angelbridge.capital" nocase
        $domain95 = "angelbridge.jp" nocase
        $domain96 = "ankanimatoka.com" nocase
        $domain97 = "annaelsa.xyz" nocase
        $domain98 = "anobaka.info" nocase
        $domain99 = "anobaka.jp" nocase
        $ip100 = "104.145.210.107"
        $ip101 = "104.168.145.52"
        $ip102 = "104.168.151.70"
        $ip103 = "104.168.198.145"
        $ip104 = "109.248.163.127"
        $ip105 = "118.70.116.154"
        $ip106 = "139.150.73.123"
        $ip107 = "140.117.91.22"
        $ip108 = "140.136.134.201"
        $ip109 = "142.11.196.106"
        $ip110 = "142.11.196.106"
        $ip111 = "142.11.206.73"
        $ip112 = "144.172.114.220"
        $ip113 = "144.172.116.143"
        $ip114 = "163.25.24.44"
        $ip115 = "163.5.254.70"
        $ip116 = "172.86.91.195"
        $ip117 = "186.183.185.94"
        $ip118 = "23.254.164.123"
        $ip119 = "23.254.164.61"
        $ip120 = "23.254.164.61"
        $ip121 = "23.254.164.92"
        $ip122 = "23.254.164.92"
        $ip123 = "23.254.164.92"
        $ip124 = "23.254.167.216"
        $ip125 = "23.254.202.223"
        $ip126 = "23.254.203.244"
        $ip127 = "23.254.203.244"
        $ip128 = "38.110.228.52"
        $ip129 = "41.85.145.164"
        $ip130 = "45.238.25.2"
        $ip131 = "45.61.129.29"
        $ip132 = "45.61.140.26"
        $ip133 = "45.61.148.134"
        $ip134 = "45.61.157.248"
        $ip135 = "45.61.163.100"
        $ip136 = "45.61.163.100"
        $ip137 = "59.152.103.205"
        $ip138 = "66.181.166.15"
        $ip139 = "83.136.208.246"
        $ip140 = "83.136.208.48"
        $ip141 = "83.136.209.22"
        $ip142 = "83.136.210.180"

    condition:
        any of them
}

rule APT_BLUEPRINT {
    meta:
        description = "Indicators associated with APT BLUEPRINT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "cloud.yourdocument.biz" nocase
        $domain1 = "swift-fraud.com" nocase

    condition:
        any of them
}

rule APT_BOOKWORM {
    meta:
        description = "Indicators associated with APT BOOKWORM"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bkmail.blogdns.com" nocase
        $domain1 = "debain.servehttp.com" nocase
        $domain2 = "linuxdns.sytes.net" nocase
        $domain3 = "news.nhknews.hk" nocase
        $domain4 = "sswmail.gotdns.com" nocase
        $domain5 = "sswwmail.gotdns.com" nocase
        $domain6 = "sysnc.sytes.net" nocase
        $domain7 = "systeminfothai.gotdns.ch" nocase
        $domain8 = "thailandbbs.ddns.net" nocase
        $domain9 = "ubuntudns.sytes.net" nocase
        $domain10 = "web12.nhknews.hk" nocase

    condition:
        any of them
}

rule APT_BOTEAM {
    meta:
        description = "Indicators associated with APT BOTEAM"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "brockendoor, black owl, hoody hyena"

    strings:
        $domain0 = "easybussy.space" nocase
        $domain1 = "icecoldwind.online" nocase
        $domain2 = "invuln.xyz" nocase
        $domain3 = "lizzardsnails.online" nocase
        $domain4 = "mgutu-vf.ru" nocase
        $domain5 = "railradman.site" nocase
        $domain6 = "tributarieshand.online" nocase
        $domain7 = "urbantvpn.online" nocase
        $domain8 = "wholewell.online" nocase
        $domain9 = "yandecx.site" nocase
        $ip10 = "213.165.60.118"
        $ip11 = "213.165.60.118"

    condition:
        any of them
}

rule APT_BUHTRAP {
    meta:
        description = "Indicators associated with APT BUHTRAP"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "UAC-0008"

    strings:
        $domain0 = "allwomens.eu" nocase
        $domain1 = "alt-2cdn.net" nocase
        $domain2 = "avidium.ru.com" nocase
        $domain3 = "corp-microsoft.com" nocase
        $domain4 = "cs1.wpc-v0cdn.org" nocase
        $domain5 = "edinstvennaya.eu" nocase
        $domain6 = "hdfilm-seyret.com" nocase
        $domain7 = "ipv6-microsoft.org" nocase
        $domain8 = "ipv6-wpnc.net" nocase
        $domain9 = "khabmama.eu" nocase
        $domain10 = "mail.nais-gov.org" nocase
        $domain11 = "nais-gov.com" nocase
        $domain12 = "nais-gov.org" nocase
        $domain13 = "ns2-dns.com" nocase
        $domain14 = "ns3-dns.com" nocase
        $domain15 = "redmond.corp-microsoft.com" nocase
        $domain16 = "secure-telemetry.net" nocase
        $domain17 = "services-glbdns2.com" nocase
        $domain18 = "shkolazhizni.eu" nocase
        $domain19 = "sibmama.eu" nocase
        $domain20 = "slingshop.ru.com" nocase
        $domain21 = "widget.forum-pokemon.com" nocase
        $domain22 = "wpc-v0cdn.org" nocase
        $domain23 = "zhenskoe-mnenie.eu" nocase

    condition:
        any of them
}

rule APT_CADETBLIZZARD {
    meta:
        description = "Indicators associated with APT CADETBLIZZARD"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "justiceua.org" nocase

    condition:
        any of them
}

rule APT_CALYPSO {
    meta:
        description = "Indicators associated with APT CALYPSO"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "aztecoo.com" nocase
        $domain1 = "blog.globnewsline.com" nocase
        $domain2 = "clark.l8t.net" nocase
        $domain3 = "dealsgle.com" nocase
        $domain4 = "draconess.com" nocase
        $domain5 = "etheraval.com" nocase
        $domain6 = "globnewsline.com" nocase
        $domain7 = "krgod.qqm8.com" nocase
        $domain8 = "mail.globnewsline.com" nocase
        $domain9 = "mail.sultris.com" nocase
        $domain10 = "membrig.com" nocase
        $domain11 = "pop3.wordmoss.com" nocase
        $domain12 = "prowesoo.com" nocase
        $domain13 = "r01.etheraval.com" nocase
        $domain14 = "rawfuns.com" nocase
        $domain15 = "rosyfund.com" nocase
        $domain16 = "streleases.com" nocase
        $domain17 = "sultris.com" nocase
        $domain18 = "surfanny.com" nocase
        $domain19 = "tc.streleases.com" nocase
        $domain20 = "teldcomtv.com" nocase
        $domain21 = "tv.teldcomtv.com" nocase
        $domain22 = "usergetacss.com" nocase
        $domain23 = "uv.usergetacss.com" nocase
        $domain24 = "waxgon.com" nocase
        $domain25 = "webmail.surfanny.com" nocase
        $domain26 = "wordmoss.com" nocase
        $domain27 = "yolkish.com" nocase
        $domain28 = "youtubemail.club" nocase
        $domain29 = "zmail.wordmoss.com" nocase
        $ip30 = "103.224.82.47"
        $ip31 = "103.224.82.47"
        $ip32 = "46.105.227.110"

    condition:
        any of them
}

rule APT_CAMARODRAGON {
    meta:
        description = "Indicators associated with APT CAMARODRAGON"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "cremessage.com" nocase
        $domain1 = "m.cremessage.com" nocase

    condition:
        any of them
}

rule APT_CARACALKITTEN {
    meta:
        description = "Indicators associated with APT CARACALKITTEN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-q-58"

    strings:
        $ip0 = "65.109.157.77"

    condition:
        any of them
}

rule APT_CARBONSPIDER {
    meta:
        description = "Indicators associated with APT CARBONSPIDER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "againcome.com" nocase
        $domain1 = "alphalanding.com" nocase
        $domain2 = "besaintegration.com" nocase
        $domain3 = "charjackyum.com" nocase
        $domain4 = "chauvinistable.com" nocase
        $domain5 = "colahasch.com" nocase
        $domain6 = "electroncador.com" nocase
        $domain7 = "gemmiparalyzed.com" nocase
        $domain8 = "jaglamorous.com" nocase
        $domain9 = "judicialance.com" nocase
        $domain10 = "neighborhoodlumish.com" nocase
        $domain11 = "petshopbook.com" nocase
        $domain12 = "podestablished.com" nocase
        $domain13 = "spontaneousance.com" nocase
        $domain14 = "spoolopedia.com" nocase
        $domain15 = "temptationone.com" nocase

    condition:
        any of them
}

rule APT_CARDERBEE {
    meta:
        description = "Indicators associated with APT CARDERBEE"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "active-microsoft.com" nocase
        $domain1 = "cdn.ofo.ac" nocase
        $domain2 = "cdn.stream-amazon.com" nocase
        $domain3 = "githubassets.akamaixed.net" nocase
        $domain4 = "gobay.info" nocase
        $domain5 = "ms-f7-sites-prod-cdn.akamaixed.net" nocase
        $domain6 = "ms-g9-sites-prod-cdn.akamaixed.net" nocase
        $domain7 = "ofo.ac" nocase
        $domain8 = "tjj.active-microsoft.com" nocase
        $ip9 = "103.151.28.11"
        $ip10 = "111.231.100.228"

    condition:
        any of them
}

rule APT_CARETO {
    meta:
        description = "Indicators associated with APT CARETO"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "appleupdt.com" nocase
        $domain1 = "carrus.gotdns.com" nocase
        $domain2 = "cherry1962.dyndns.org" nocase
        $domain3 = "ctronlinenews.dyndns.tv" nocase
        $domain4 = "dfup.selfip.org" nocase
        $domain5 = "fast8.homeftp.org" nocase
        $domain6 = "gx5639.dyndns.tv" nocase
        $domain7 = "helpcenter1it6238.cz.cc" nocase
        $domain8 = "helpcenter2br6932.cc" nocase
        $domain9 = "isaserver.minrex.gov.cu" nocase
        $domain10 = "karpeskmon.dyndns.org" nocase
        $domain11 = "linkconf.net" nocase
        $domain12 = "mango66.dyndns.org" nocase
        $domain13 = "msupdate.ath.cx" nocase
        $domain14 = "msupdt.com" nocase
        $domain15 = "nav1002.ath.cx" nocase
        $domain16 = "nthost.shacknet.nu" nocase
        $domain17 = "oco-231-ms.xns01.com" nocase
        $domain18 = "pininfarina.dynalias.com" nocase
        $domain19 = "pl400.dyndns.org" nocase
        $domain20 = "prosoccer1.dyndns.info" nocase
        $domain21 = "prosoccer2.dyndns.info" nocase
        $domain22 = "redirserver.net" nocase
        $domain23 = "ricush.ath.cx" nocase
        $domain24 = "services.serveftp.org" nocase
        $domain25 = "sv.serveftp.org" nocase
        $domain26 = "swupdt.com" nocase
        $domain27 = "takami.podzone.net" nocase
        $domain28 = "tunga.homedns.org" nocase
        $domain29 = "updates.homeftp.org" nocase
        $domain30 = "wqq.dyndns.org" nocase
        $domain31 = "wwnav.selfip.net" nocase

    condition:
        any of them
}

rule APT_CAVERNMANTICORE {
    meta:
        description = "Indicators associated with APT CAVERNMANTICORE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "cav3rn"

    strings:
        $domain0 = "adserviceupdate.com" nocase
        $domain1 = "api.zapretmusic.com" nocase
        $domain2 = "app.zapretmusic.com" nocase
        $domain3 = "auth.hospitalinstallation.com" nocase
        $domain4 = "google.com.hospitalinstallation.com" nocase
        $domain5 = "hospitalinstallation.com" nocase
        $domain6 = "hygienehistory.com" nocase
        $domain7 = "update.myddns.me" nocase
        $domain8 = "zapretmusic.com" nocase

    condition:
        any of them
}

rule APT_CDT {
    meta:
        description = "Indicators associated with APT CDT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bowenpres.com" nocase
        $domain1 = "bowenpress.net" nocase
        $domain2 = "bowenpress.org" nocase
        $domain3 = "bowenpross.com" nocase
        $domain4 = "chinadagitaltimes.net" nocase
        $domain5 = "datalink.one" nocase
        $domain6 = "epochatimes.com" nocase
        $domain7 = "nhknews.hk" nocase
        $domain8 = "rooter.tk" nocase
        $domain9 = "secuerserver.com" nocase
        $domain10 = "tibetonline.info" nocase
        $domain11 = "vancouversun.us" nocase
        $domain12 = "vnews.hk" nocase
        $domain13 = "voanews.hk" nocase
        $domain14 = "yomiuri.us" nocase

    condition:
        any of them
}

rule APT_CHAFER {
    meta:
        description = "Indicators associated with APT CHAFER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt39, chafer, itg07"

    strings:
        $domain0 = "0ffice36o.com" nocase
        $domain1 = "100ostad.ir" nocase
        $domain2 = "acrobatverify.com" nocase
        $domain3 = "adobelicence.com" nocase
        $domain4 = "adpolicer.org" nocase
        $domain5 = "anyportals.com" nocase
        $domain6 = "apigoogle-accounts.biz" nocase
        $domain7 = "ccloudflare.com" nocase
        $domain8 = "chembook.ir" nocase
        $domain9 = "cloudipnameserver.com" nocase
        $domain10 = "ctci.ir" nocase
        $domain11 = "defender-update.com" nocase
        $domain12 = "dnmails.gq" nocase
        $domain13 = "dnrslv.gq" nocase
        $domain14 = "dropboxengine.com" nocase
        $domain15 = "elfdomainone.com" nocase
        $domain16 = "eseses.tk" nocase
        $domain17 = "facedomainpc.com" nocase
        $domain18 = "facedomaintv.com" nocase
        $domain19 = "fullplayersoftware.com" nocase
        $domain20 = "googie.email" nocase
        $domain21 = "hpserver.online" nocase
        $domain22 = "idc-team.net" nocase
        $domain23 = "irchemistry.com" nocase
        $domain24 = "irchemistry.net" nocase
        $domain25 = "j-alam.com" nocase
        $domain26 = "jevxvideo.com" nocase
        $domain27 = "jscript.online" nocase
        $domain28 = "ktci.ir" nocase
        $domain29 = "lifedomainwar.com" nocase
        $domain30 = "lowconnectivity.com" nocase
        $domain31 = "mailservice-verify.stream" nocase
        $domain32 = "microsoftcert.xyz" nocase
        $domain33 = "microsoftfixer.com" nocase
        $domain34 = "milanionline.ir" nocase
        $domain35 = "mobily-sa.com" nocase
        $domain36 = "msn-com.dynu.net" nocase
        $domain37 = "msnconnection.com" nocase
        $domain38 = "mycrossweb.com" nocase
        $domain39 = "nvidia-services.com" nocase
        $domain40 = "offsetweb.com" nocase
        $domain41 = "redjewelry.biz" nocase
        $domain42 = "sabre-airlinesolutions.com" nocase
        $domain43 = "sabre-css.com" nocase
        $domain44 = "sadostad.com" nocase
        $domain45 = "sadostad.ir" nocase
        $domain46 = "saveingone.com" nocase
        $domain47 = "skf-group.info" nocase
        $domain48 = "softwareplayertop.com" nocase
        $domain49 = "srvuptcloud.com" nocase
        $domain50 = "stackwebonline.com" nocase
        $domain51 = "supermario2018.com" nocase
        $domain52 = "telenorco.com" nocase
        $domain53 = "tleanalyser.com" nocase
        $domain54 = "turkiyeburslari.tk" nocase
        $domain55 = "update-microsoft.space" nocase
        $domain56 = "updatenodes.site" nocase
        $domain57 = "updatesecuritypatch.com" nocase
        $domain58 = "verify-accounts-support.com" nocase
        $domain59 = "websys-corpo.com" nocase
        $domain60 = "wherisdomaintv.com" nocase
        $domain61 = "whoisdomainpc.com" nocase
        $domain62 = "win10-update.com" nocase
        $domain63 = "win7-update.com" nocase
        $domain64 = "windows-update.dynu.net" nocase
        $domain65 = "xn--mgbfv9eh74d.com" nocase
        $domain66 = "yjksdrl.tk" nocase
        $domain67 = "ytb.services" nocase

    condition:
        any of them
}

rule APT_CHAMELGANG {
    meta:
        description = "Indicators associated with APT CHAMELGANG"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "camofei"

    strings:
        $domain0 = "api.microsofed.com" nocase
        $domain1 = "app.centralgoogle.com" nocase
        $domain2 = "app.tstartel.org" nocase
        $domain3 = "appupdate.ibmlotus.net" nocase
        $domain4 = "auth.newtrendmicro.com" nocase
        $domain5 = "cdn-chrome.com" nocase
        $domain6 = "centralgoogle.com" nocase
        $domain7 = "cn.mcafee-service.us.com" nocase
        $domain8 = "collector.centralgoogle.com" nocase
        $domain9 = "content.centralgoogle.com" nocase
        $domain10 = "content.newtrendmicro.com" nocase
        $domain11 = "contents.newtrendmicro.com" nocase
        $domain12 = "derbox.centralgoogle.com" nocase
        $domain13 = "docs.microsoft-support.net" nocase
        $domain14 = "download.softupdate-online.top" nocase
        $domain15 = "downloads.softupdate-online.top" nocase
        $domain16 = "en.mcafee-service.us.com" nocase
        $domain17 = "funding-exchange.org" nocase
        $domain18 = "helpdisk.ibmlotus.net" nocase
        $domain19 = "ibmlotus.net" nocase
        $domain20 = "internet.softupdate-online.top" nocase
        $domain21 = "jumper.funding-exchange.org" nocase
        $domain22 = "kaspernsky.com" nocase
        $domain23 = "login.cdn-chrome.com" nocase
        $domain24 = "mail.ibmlotus.net" nocase
        $domain25 = "mail.tstartel.org" nocase
        $domain26 = "market.newtrendmicro.com" nocase
        $domain27 = "mcafee-service.us.com" nocase
        $domain28 = "mcafee-upgrade.com" nocase
        $domain29 = "microsofed.com" nocase
        $domain30 = "microsoft-support.net" nocase
        $domain31 = "newtrendmicro.com" nocase
        $domain32 = "ns1.marocfamily.com" nocase
        $domain33 = "ns1.marocfamilym.com" nocase
        $domain34 = "ns1.marocfamilyx.com" nocase
        $domain35 = "ns1.spezialsex.com" nocase
        $domain36 = "ns2.marocfamily.com" nocase
        $domain37 = "ns2.spezialsex.com" nocase
        $domain38 = "ns30.mayashopping.net" nocase
        $domain39 = "ns31.mayashopping.net" nocase
        $domain40 = "online.softupdate-online.top" nocase
        $domain41 = "os.microsoft-support.net" nocase
        $domain42 = "search.ibmlotus.net" nocase
        $domain43 = "snn1.mhysl.org" nocase
        $domain44 = "snn2.mhysl.org" nocase
        $domain45 = "snn3.mhysl.org" nocase
        $domain46 = "softupdate-online.top" nocase
        $domain47 = "ssl.mcafee-upgrade.com" nocase
        $domain48 = "static.mhysl.org" nocase
        $domain49 = "test.mcafee-upgrade.com" nocase
        $domain50 = "tstartel.org" nocase
        $domain51 = "tw.mcafee-upgrade.com" nocase
        $domain52 = "update.kaspernsky.com" nocase
        $domain53 = "update.microsoft-support.net" nocase
        $domain54 = "update.softupdate-online.top" nocase
        $domain55 = "upgrade.ibmlotus.net" nocase
        $domain56 = "upgrade.newtrendmicro.com" nocase
        $domain57 = "us.mcafee-upgrade.com" nocase
        $domain58 = "webmail.tstartel.org" nocase
        $ip59 = "115.144.122.8"
        $ip60 = "45.91.24.73"

    condition:
        any of them
}

rule APT_CHARMINGKITTEN {
    meta:
        description = "Indicators associated with APT CHARMINGKITTEN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt35, apt42, apt-c-51"

    strings:
        $domain0 = "012mail-net-uwclogin.ml" nocase
        $domain1 = "0brandaeyes0.xyz" nocase
        $domain2 = "0standavalue0.xyz" nocase
        $domain3 = "0storageatools0.xyz" nocase
        $domain4 = "1drv.casa" nocase
        $domain5 = "1drv.cyou" nocase
        $domain6 = "1drv.icu" nocase
        $domain7 = "1drv.live" nocase
        $domain8 = "1drv.online" nocase
        $domain9 = "1drv.surf" nocase
        $domain10 = "1drv.xyz" nocase
        $domain11 = "1stemployer.com" nocase
        $domain12 = "1stl.ink" nocase
        $domain13 = "30min-ergmeeting.com" nocase
        $domain14 = "30min-ergmeeting.net" nocase
        $domain15 = "30min-smartsight-hr.com" nocase
        $domain16 = "30min-smartsight.com" nocase
        $domain17 = "30min-ziprecruiter.com" nocase
        $domain18 = "30min-ziprecruiterhr.com" nocase
        $domain19 = "30minmeeting-quality.com" nocase
        $domain20 = "30minmeetinghr.com" nocase
        $domain21 = "30minziprecruiterhr.net" nocase
        $domain22 = "3dauth.live" nocase
        $domain23 = "3dconfirrnation.com" nocase
        $domain24 = "8475.freelancedeveloper.site" nocase
        $domain25 = "8ghefkwdvbfdsg3asdf1.com" nocase
        $domain26 = "academy-update.com" nocase
        $domain27 = "accesscheckout.online" nocase
        $domain28 = "accessverification.online" nocase
        $domain29 = "acconut-mail.com" nocase
        $domain30 = "acconut-signin.com" nocase
        $domain31 = "acconut-verify.com" nocase
        $domain32 = "account-customerservice.com" nocase
        $domain33 = "account-drive.com" nocase
        $domain34 = "account-dropbox.net" nocase
        $domain35 = "account-google.co" nocase
        $domain36 = "account-log-user-verify-mail.com" nocase
        $domain37 = "account-login.net" nocase
        $domain38 = "account-logins.com" nocase
        $domain39 = "account-permission-mail-user.com" nocase
        $domain40 = "account-profile-users.info" nocase
        $domain41 = "account-servicemanagement.info" nocase
        $domain42 = "account-servicerecovery.com" nocase
        $domain43 = "account-servieemanagement.info" nocase
        $domain44 = "account-signin-myaccount-users.ga" nocase
        $domain45 = "account-signin.com" nocase
        $domain46 = "account-siqnin.com" nocase
        $domain47 = "account-support-user.com" nocase
        $domain48 = "account-user-permission-account.com" nocase
        $domain49 = "account-user-verify-mail.com" nocase
        $domain50 = "account-user.com" nocase
        $domain51 = "account-users-mail.com" nocase
        $domain52 = "account-verifiy.net" nocase
        $domain53 = "accountroyal.com" nocase
        $domain54 = "accounts-apple.com" nocase
        $domain55 = "accounts-drive.com" nocase
        $domain56 = "accounts-googelmail.com" nocase
        $domain57 = "accounts-googelmails.com" nocase
        $domain58 = "accounts-logins.net" nocase
        $domain59 = "accounts-mails.com" nocase
        $domain60 = "accounts-manager.info" nocase
        $domain61 = "accounts-service.support" nocase
        $domain62 = "accounts-support.services" nocase
        $domain63 = "accounts-web-maii.com" nocase
        $domain64 = "accounts-web-mail.com" nocase
        $domain65 = "accounts-yahoo.us" nocase
        $domain66 = "accounts.google.live-meet.blog" nocase
        $domain67 = "accounts.google.live-meet.cfd" nocase
        $domain68 = "accounts.google.live-meet.cloud" nocase
        $domain69 = "accounts.google.live-meet.info" nocase
        $domain70 = "accounts.google.network-show.online" nocase
        $domain71 = "accountservice.support" nocase
        $domain72 = "accountsrecovery.ddns.net" nocase
        $domain73 = "accountsservice-support.com" nocase
        $domain74 = "accountts-google.com" nocase
        $domain75 = "accredit-navigation.online" nocase
        $domain76 = "accredit-validity.ddns.net" nocase
        $domain77 = "accredit-validity.online" nocase
        $domain78 = "accredit.network" nocase
        $domain79 = "accredit.validity.werifcattion.info" nocase
        $domain80 = "accunt-loqin.ml" nocase
        $domain81 = "accurate-sprout-porpoise.glitch.me" nocase
        $domain82 = "accurateprivacy.online" nocase
        $domain83 = "ace-capitalpartners.ddns.net" nocase
        $domain84 = "acounts-qooqie-con.ml" nocase
        $domain85 = "activeeditor.info" nocase
        $domain86 = "activehealthlab.azurewebsites.net" nocase
        $domain87 = "activespiritluth.eastus.cloudapp.azure.com" nocase
        $domain88 = "activities-recovery-options.info" nocase
        $domain89 = "activities-servicesnotification.info" nocase
        $domain90 = "activity-confirmationservice.info" nocase
        $domain91 = "activity-session-recovery.info" nocase
        $domain92 = "actor.rap-art.info" nocase
        $domain93 = "acupuncturebentonville.com" nocase
        $domain94 = "adams-cooling.online" nocase
        $domain95 = "addons-mozilla.download" nocase
        $domain96 = "admin-stable-right.top" nocase
        $domain97 = "admin.cheap-case.site" nocase
        $domain98 = "admiscion.online" nocase
        $domain99 = "admit-roar-frame.top" nocase
        $ip100 = "103.57.251.153"
        $ip101 = "103.57.251.153"
        $ip102 = "136.243.108.10"
        $ip103 = "136.243.108.10"
        $ip104 = "136.243.108.10"
        $ip105 = "136.243.108.10"
        $ip106 = "136.243.108.10"
        $ip107 = "136.243.108.10"
        $ip108 = "136.243.108.10"
        $ip109 = "136.243.108.10"
        $ip110 = "136.243.108.10"
        $ip111 = "136.243.108.11"
        $ip112 = "136.243.108.11"
        $ip113 = "136.243.108.11"
        $ip114 = "136.243.108.11"
        $ip115 = "136.243.108.11"
        $ip116 = "136.243.108.11"
        $ip117 = "136.243.108.11"
        $ip118 = "136.243.108.11"
        $ip119 = "136.243.108.11"
        $ip120 = "136.243.108.12"
        $ip121 = "136.243.108.12"
        $ip122 = "136.243.108.12"
        $ip123 = "136.243.108.12"
        $ip124 = "136.243.108.12"
        $ip125 = "136.243.108.12"
        $ip126 = "136.243.108.12"
        $ip127 = "136.243.108.12"
        $ip128 = "136.243.108.12"
        $ip129 = "136.243.108.13"
        $ip130 = "136.243.108.13"
        $ip131 = "136.243.108.13"
        $ip132 = "136.243.108.13"
        $ip133 = "136.243.108.13"
        $ip134 = "136.243.108.13"
        $ip135 = "136.243.108.13"
        $ip136 = "136.243.108.13"
        $ip137 = "136.243.108.13"
        $ip138 = "136.243.108.14"
        $ip139 = "136.243.108.14"
        $ip140 = "136.243.108.14"
        $ip141 = "136.243.108.14"
        $ip142 = "136.243.108.14"
        $ip143 = "136.243.108.14"
        $ip144 = "136.243.108.14"
        $ip145 = "136.243.108.14"
        $ip146 = "136.243.108.14"
        $ip147 = "136.243.108.9"
        $ip148 = "136.243.108.9"
        $ip149 = "136.243.108.9"

    condition:
        any of them
}

rule APT_CLEAVER {
    meta:
        description = "Indicators associated with APT CLEAVER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "doosan-job.com" nocase
        $domain1 = "downloadsservers.com" nocase
        $domain2 = "drivercenterupdate.com" nocase
        $domain3 = "easyresumecreatorpro.com" nocase
        $domain4 = "googleproductupdate.net" nocase
        $domain5 = "microsoftmiddleast.com" nocase
        $domain6 = "microsoftserverupdate.com" nocase
        $domain7 = "microsoftwindowsresources.com" nocase
        $domain8 = "microsoftwindowsupdate.net" nocase
        $domain9 = "northropgrumman.net" nocase
        $domain10 = "teledyne-jobs.com" nocase
        $domain11 = "windowscentralupdate.com" nocase
        $domain12 = "windowssecurityupdate.com" nocase
        $domain13 = "windowsserverupdate.com" nocase
        $domain14 = "windowsupdateserver.com" nocase

    condition:
        any of them
}

rule APT_CLOUDATLAS {
    meta:
        description = "Indicators associated with APT CLOUDATLAS"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "APT-LY-1007, CloudFall, CyrillicRAT"

    strings:
        $domain0 = "2020-windows.com" nocase
        $domain1 = "3i.hilsabecks.net" nocase
        $domain2 = "56.msgntfsys.link" nocase
        $domain3 = "7h.ahmetgurses.net" nocase
        $domain4 = "advancestore.workers.dev" nocase
        $domain5 = "agent-group.org" nocase
        $domain6 = "ahmetgurses.net" nocase
        $domain7 = "aitoall.ru" nocase
        $domain8 = "api-help.com" nocase
        $domain9 = "api.office365online.workers.dev" nocase
        $domain10 = "apkcrypter.com" nocase
        $domain11 = "archive-downloader.com" nocase
        $domain12 = "arendelle.ru" nocase
        $domain13 = "asia.office365-cloud.workers.dev" nocase
        $domain14 = "avito-service.net" nocase
        $domain15 = "azureblog.info" nocase
        $domain16 = "becloud.website" nocase
        $domain17 = "billet-ru.net" nocase
        $domain18 = "blackberry-support.herokuapp.com" nocase
        $domain19 = "bot.fortune-wheel.ru" nocase
        $domain20 = "brexitimpact.com" nocase
        $domain21 = "bryksina.ru" nocase
        $domain22 = "checklicensekey.com" nocase
        $domain23 = "cityru-travel.org" nocase
        $domain24 = "cloud.archive-downloader.com" nocase
        $domain25 = "cloud.digitalstorage.workers.dev" nocase
        $domain26 = "comparelicense.com" nocase
        $domain27 = "connectcosmo.click" nocase
        $domain28 = "connectcosmo.online" nocase
        $domain29 = "content-protect.net" nocase
        $domain30 = "control-issue.net" nocase
        $domain31 = "copilotgptawer.cfd" nocase
        $domain32 = "cortanaupdater.info" nocase
        $domain33 = "cosmo-service.org" nocase
        $domain34 = "curly-waterfall-360d.fetrikekke531.workers.dev" nocase
        $domain35 = "dc-microsoft.workers.dev" nocase
        $domain36 = "desktoppreview.com" nocase
        $domain37 = "dezinsekciya-top.ru" nocase
        $domain38 = "digitalstorage.workers.dev" nocase
        $domain39 = "doc-fid.com" nocase
        $domain40 = "documents.publicserver.workers.dev" nocase
        $domain41 = "driver-key.com" nocase
        $domain42 = "driver-updated.com" nocase
        $domain43 = "driversolution.net" nocase
        $domain44 = "e-aks.uz" nocase
        $domain45 = "e-government-pk.com" nocase
        $domain46 = "e-govoffice.com" nocase
        $domain47 = "ecolines.es" nocase
        $domain48 = "elycleu.click" nocase
        $domain49 = "eu.microsoft-365.workers.dev" nocase
        $domain50 = "eurasia-research.org" nocase
        $domain51 = "exactsynchtime.ru" nocase
        $domain52 = "falling-haze-1812.jerkufetra754.workers.dev" nocase
        $domain53 = "falling-haze-1813.jerkufetra754.workers.dev" nocase
        $domain54 = "fatobara.com" nocase
        $domain55 = "fcauditsp.ru" nocase
        $domain56 = "fetrikekke531.workers.dev" nocase
        $domain57 = "flashsupport.org" nocase
        $domain58 = "fmsru.ru" nocase
        $domain59 = "fortune-wheel.ru" nocase
        $domain60 = "ftp.arendelle.ru" nocase
        $domain61 = "ftp.bryksina.ru" nocase
        $domain62 = "ftp.dezinsekciya-top.ru" nocase
        $domain63 = "ftp.wolrpg.ru" nocase
        $domain64 = "ftp.zhk-ambassador.ru" nocase
        $domain65 = "get-news-online.com" nocase
        $domain66 = "gettemplate.org" nocase
        $domain67 = "gimnazija.org" nocase
        $domain68 = "gmocloudhosting.com" nocase
        $domain69 = "gosportal.net" nocase
        $domain70 = "haarmannsi.cz" nocase
        $domain71 = "hilsabecks.net" nocase
        $domain72 = "host-tools.net" nocase
        $domain73 = "hostscontrol.com" nocase
        $domain74 = "http-updater.hs.vc" nocase
        $domain75 = "ieobil.asia" nocase
        $domain76 = "information-model.net" nocase
        $domain77 = "infovesty.ru" nocase
        $domain78 = "interior-gov.com" nocase
        $domain79 = "iphoneupdatecheck.com" nocase
        $domain80 = "iznews.net" nocase
        $domain81 = "jerkufetra754.workers.dev" nocase
        $domain82 = "kjzxpe.ru" nocase
        $domain83 = "live-media.org" nocase
        $domain84 = "liveinfo.org" nocase
        $domain85 = "log1inbox.com" nocase
        $domain86 = "mail.aitoall.ru" nocase
        $domain87 = "mail.arendelle.ru" nocase
        $domain88 = "mail.bryksina.ru" nocase
        $domain89 = "mail.dezinsekciya-top.ru" nocase
        $domain90 = "mail.msgntfsys.link" nocase
        $domain91 = "mail.wolrpg.ru" nocase
        $domain92 = "mail.zhk-ambassador.ru" nocase
        $domain93 = "managements.wireless-log.net" nocase
        $domain94 = "marketru.net" nocase
        $domain95 = "mcdrugs.com" nocase
        $domain96 = "medoaaustinsci.info" nocase
        $domain97 = "mehafon.com" nocase
        $domain98 = "micron-media.com" nocase
        $domain99 = "microsftupdetes.com" nocase
        $ip100 = "168.100.11.142"
        $ip101 = "185.252.147.12"
        $ip102 = "185.252.147.12"
        $ip103 = "185.252.147.12"
        $ip104 = "194.190.153.182"
        $ip105 = "5.252.179.45"
        $ip106 = "94.232.248.34"

    condition:
        any of them
}

rule APT_CLOUDWIZARD {
    meta:
        description = "Indicators associated with APT CLOUDWIZARD"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "curveroad.com" nocase

    condition:
        any of them
}

rule APT_COBALTDICKENS {
    meta:
        description = "Indicators associated with APT COBALTDICKENS"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "ta407, silent librarian, mabna institute"

    strings:
        $domain0 = "12st.me" nocase
        $domain1 = "12xb.me" nocase
        $domain2 = "1edu.in" nocase
        $domain3 = "1ezpro.xyz" nocase
        $domain4 = "1r3o.me" nocase
        $domain5 = "28ag.me" nocase
        $domain6 = "32ex.me" nocase
        $domain7 = "33qa.me" nocase
        $domain8 = "67vr.me" nocase
        $domain9 = "67yt.me" nocase
        $domain10 = "ac.uk.libte.me" nocase
        $domain11 = "aclib.me" nocase
        $domain12 = "acuk.me" nocase
        $domain13 = "adfs.goucher.adui.me" nocase
        $domain14 = "adfs.goucher.elru.me" nocase
        $domain15 = "adfs.goucher.pdlu.me" nocase
        $domain16 = "adfs.goucher.unde.me" nocase
        $domain17 = "adfs.lincoln.ac.uk.itlib.me" nocase
        $domain18 = "adui.me" nocase
        $domain19 = "aill.cf" nocase
        $domain20 = "aill.nl" nocase
        $domain21 = "allib.me" nocase
        $domain22 = "anvc.me" nocase
        $domain23 = "aroe.me" nocase
        $domain24 = "asoec.me" nocase
        $domain25 = "atll.tk" nocase
        $domain26 = "atna.cf" nocase
        $domain27 = "atti.cf" nocase
        $domain28 = "auth.bath.ac.uk.ctit.cf" nocase
        $domain29 = "auth.bath.ac.uk.ctit.tk" nocase
        $domain30 = "auth.bath.ac.uk.ncev.me" nocase
        $domain31 = "auth.bath.ac.uk.titt.ml" nocase
        $domain32 = "auth.bath.ac.uk.ukns.me" nocase
        $domain33 = "auth.bath.ac.uk.ztit.cf" nocase
        $domain34 = "auth.miamioh.eduo.me" nocase
        $domain35 = "avne.me" nocase
        $domain36 = "azll.cf" nocase
        $domain37 = "azll.tk" nocase
        $domain38 = "azlll.cf" nocase
        $domain39 = "aztt.tk" nocase
        $domain40 = "balamand.edu.lb.ezlibin.com" nocase
        $domain41 = "bath.ac.uk.ncev.me" nocase
        $domain42 = "bcfk.me" nocase
        $domain43 = "bdhw.me" nocase
        $domain44 = "bib.mdh.se.ezlibin.com" nocase
        $domain45 = "bib.mdh.se.libinpro.xyz" nocase
        $domain46 = "bidi.uam.mx.logezpro.xyz" nocase
        $domain47 = "blackboard.gcal.crev.me" nocase
        $domain48 = "blackboard.stonybrook.ernn.me" nocase
        $domain49 = "blackboard.stonybrook.nrni.me" nocase
        $domain50 = "blackboard.usc.caer.me" nocase
        $domain51 = "blibo.ga" nocase
        $domain52 = "bolton.ac.rnuk.me" nocase
        $domain53 = "bolton.ac.rvuk.me" nocase
        $domain54 = "bolton.ac.uk.libte.me" nocase
        $domain55 = "bolton.ac.uk.rulk.me" nocase
        $domain56 = "bradley.eulib.me" nocase
        $domain57 = "bradley.ledu.me" nocase
        $domain58 = "bradley.lible.me" nocase
        $domain59 = "bradley.rvedu.me" nocase
        $domain60 = "bradley.ulibe.me" nocase
        $domain61 = "bradley.zedu.me" nocase
        $domain62 = "c23e.me" nocase
        $domain63 = "caer.me" nocase
        $domain64 = "canm.me" nocase
        $domain65 = "canvas.bham.vueu.me" nocase
        $domain66 = "canvas.sydney.sunu.me" nocase
        $domain67 = "canvas.ucdavis.snnu.me" nocase
        $domain68 = "cardiff.ac.erlib.me" nocase
        $domain69 = "cardiff.ac.plib.me" nocase
        $domain70 = "cardiff.acuk.me" nocase
        $domain71 = "cas.conncoll.ebui.me" nocase
        $domain72 = "cas.csufresno.eduir.me" nocase
        $domain73 = "cas.fsu.edu.libg.ml" nocase
        $domain74 = "cas.lcc.edu.llrn.me" nocase
        $domain75 = "cas.lcc.llrn.me" nocase
        $domain76 = "cas.thm.de.itlib.me" nocase
        $domain77 = "cas.thm.de.servisedesk.me" nocase
        $domain78 = "catalogue.londonmet.ac.uk.cnlib.me" nocase
        $domain79 = "cave.gq" nocase
        $domain80 = "ccli.cf" nocase
        $domain81 = "cedu.me" nocase
        $domain82 = "cett.cf" nocase
        $domain83 = "ciff.login.nerb.me" nocase
        $domain84 = "cill.ml" nocase
        $domain85 = "clll.cf" nocase
        $domain86 = "clll.nl" nocase
        $domain87 = "clll.tk" nocase
        $domain88 = "cllt.cf" nocase
        $domain89 = "cllt.tk" nocase
        $domain90 = "cnen.cf" nocase
        $domain91 = "cnlib.me" nocase
        $domain92 = "cnma.cf" nocase
        $domain93 = "cnna.me" nocase
        $domain94 = "cntt.cf" nocase
        $domain95 = "comn.me" nocase
        $domain96 = "conncoll.ebui.me" nocase
        $domain97 = "cornn.me" nocase
        $domain98 = "cqgp.me" nocase
        $domain99 = "crev.me" nocase

    condition:
        any of them
}

rule APT_CODOSO {
    meta:
        description = "Indicators associated with APT CODOSO"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt19, codoso, c0d0so0"

    strings:
        $domain0 = "EmpireB1ue.com" nocase
        $domain1 = "ameteksen.com" nocase
        $domain2 = "asconline.we11point.com" nocase
        $domain3 = "assso.net" nocase
        $domain4 = "autodiscover.2bunny.com" nocase
        $domain5 = "b.gnisoft.com" nocase
        $domain6 = "capstoneturbine.cechire.com" nocase
        $domain7 = "caref1rst.com" nocase
        $domain8 = "careflrst.com" nocase
        $domain9 = "client.gnisoft.com" nocase
        $domain10 = "extcitrix.we11point.com" nocase
        $domain11 = "facefuture.us" nocase
        $domain12 = "gifas.blogsite.org" nocase
        $domain13 = "gifas.cechire.com" nocase
        $domain14 = "giga.gnisoft.com" nocase
        $domain15 = "gnisoft.com" nocase
        $domain16 = "google-dash.com" nocase
        $domain17 = "googlewebcache.com" nocase
        $domain18 = "healthslie.com" nocase
        $domain19 = "hrsolutions.we11point.com" nocase
        $domain20 = "icbcqsz.com" nocase
        $domain21 = "images.googlewebcache.com" nocase
        $domain22 = "jbossas.org" nocase
        $domain23 = "kaspersyk.com" nocase
        $domain24 = "lyncdiscover.2bunny.com" nocase
        $domain25 = "me.we11point.com" nocase
        $domain26 = "microsoft-cache.com" nocase
        $domain27 = "mycitrix.we11point.com" nocase
        $domain28 = "myhr.we11point.com" nocase
        $domain29 = "oa.ameteksen.com" nocase
        $domain30 = "oa.technical-requre.com" nocase
        $domain31 = "oa.trustneser.com" nocase
        $domain32 = "outlookssl.com" nocase
        $domain33 = "polarroute.com" nocase
        $domain34 = "premrera.com" nocase
        $domain35 = "prennera.com" nocase
        $domain36 = "savmpet.com" nocase
        $domain37 = "sfo02s01-in-f2.cloudsend.net" nocase
        $domain38 = "sharepoint-vaeit.com" nocase
        $domain39 = "sinmoung.com" nocase
        $domain40 = "smi1egate.com" nocase
        $domain41 = "smtp.outlookssl.com" nocase
        $domain42 = "ssl-vaeit.com" nocase
        $domain43 = "ssl-vait.com" nocase
        $domain44 = "supermanbox.org" nocase
        $domain45 = "svn1.smi1egate.com" nocase
        $domain46 = "tk-in-f156.2bunny.com" nocase
        $domain47 = "topsec2014.com" nocase
        $domain48 = "vipreclod.com" nocase
        $domain49 = "vpn.premrera.com" nocase
        $domain50 = "vpn.we11point.com" nocase
        $domain51 = "vpn2.smi1egate.com" nocase
        $domain52 = "we11point.com" nocase
        $domain53 = "webmail.kaspersyk.com" nocase
        $domain54 = "webmail.vipreclod.com" nocase
        $domain55 = "wiki-vaeit.com" nocase
        $domain56 = "ysims.com" nocase
        $ip57 = "104.223.34.198"
        $ip58 = "192.95.36.61"

    condition:
        any of them
}

rule APT_COLDRIVER {
    meta:
        description = "Indicators associated with APT COLDRIVER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "calisto, ta446, unc3707"

    strings:
        $domain0 = "access-confirmation.com" nocase
        $domain1 = "account.officesecure.online" nocase
        $domain2 = "accounts-ukr.com" nocase
        $domain3 = "accounts.hypertexttech.com" nocase
        $domain4 = "accounts.kv-ukr.net" nocase
        $domain5 = "accounts.ukr-mails.net" nocase
        $domain6 = "accounts.ukr-reset.email" nocase
        $domain7 = "accsua.com" nocase
        $domain8 = "accsukr.com" nocase
        $domain9 = "advath.officesecure.online" nocase
        $domain10 = "alightcruellane.net" nocase
        $domain11 = "allow-access.com" nocase
        $domain12 = "ankaramuhaseben.com" nocase
        $domain13 = "antibots-service.com" nocase
        $domain14 = "apicomcloud.com" nocase
        $domain15 = "app-sharcpoint.com" nocase
        $domain16 = "app-sharcpointe.com" nocase
        $domain17 = "app-sharcpolnt.com" nocase
        $domain18 = "app-sharcpolnte.com" nocase
        $domain19 = "applicationformsubmit.me" nocase
        $domain20 = "appsharcpointe.com" nocase
        $domain21 = "appsharcpointes.com" nocase
        $domain22 = "appssharcpointe.com" nocase
        $domain23 = "as-mvd.ru" nocase
        $domain24 = "attach-docs.com" nocase
        $domain25 = "attach-update.com" nocase
        $domain26 = "auth.officesecure.online" nocase
        $domain27 = "authpoint.usa.officesecure.online" nocase
        $domain28 = "betmgm-support.com" nocase
        $domain29 = "betus-us.info" nocase
        $domain30 = "bigdatabroadway.com" nocase
        $domain31 = "bittechllc.net" nocase
        $domain32 = "blintepeeste.org" nocase
        $domain33 = "blueskynetwork-drive.com" nocase
        $domain34 = "blueskynetwork-shared.com" nocase
        $domain35 = "botguard-checker.com" nocase
        $domain36 = "botguard-web.com" nocase
        $domain37 = "cache-dns-forwarding.com" nocase
        $domain38 = "cache-dns-preview.com" nocase
        $domain39 = "cache-dns.com" nocase
        $domain40 = "cache-docs.com" nocase
        $domain41 = "cache-pdf.com" nocase
        $domain42 = "cache-pdf.online" nocase
        $domain43 = "cache-services.live" nocase
        $domain44 = "captchanom.top" nocase
        $domain45 = "centeritdefcity.com" nocase
        $domain46 = "challenge-identifier.com" nocase
        $domain47 = "challenge-share.com" nocase
        $domain48 = "changepassword-ukr.net" nocase
        $domain49 = "checker-bot.com" nocase
        $domain50 = "checkscreenit.com" nocase
        $domain51 = "cija-docs.com" nocase
        $domain52 = "cija-drive.com" nocase
        $domain53 = "cityessentials.net" nocase
        $domain54 = "client-serviceauth0.com" nocase
        $domain55 = "cloud-docs.com" nocase
        $domain56 = "cloud-drive.live" nocase
        $domain57 = "cloud-mail.online" nocase
        $domain58 = "cloud-safety.online" nocase
        $domain59 = "cloud-sharcpoint.com" nocase
        $domain60 = "cloud-sharcpointe.com" nocase
        $domain61 = "cloud-sharcpolnte.com" nocase
        $domain62 = "cloud-sharepolnt.com" nocase
        $domain63 = "cloud-storage.live" nocase
        $domain64 = "cloud-us.online" nocase
        $domain65 = "cloudcpanelhost.com" nocase
        $domain66 = "clouddefsystems.com" nocase
        $domain67 = "cloudinfodata.com" nocase
        $domain68 = "cloudithub.com" nocase
        $domain69 = "cloudmediaportal.com" nocase
        $domain70 = "cloudrootstorage.com" nocase
        $domain71 = "cloudsharepolnte.com" nocase
        $domain72 = "commandentrance.com" nocase
        $domain73 = "computertechdirectsystems.com" nocase
        $domain74 = "computingtechstudio.com" nocase
        $domain75 = "configuregatewayglobal.com" nocase
        $domain76 = "controlgatestorage.com" nocase
        $domain77 = "controlsstoragedirect.com" nocase
        $domain78 = "controlstoragesolutions.com" nocase
        $domain79 = "cryptdatagate.com" nocase
        $domain80 = "cryptotechdirect.com" nocase
        $domain81 = "cryptothistech.com" nocase
        $domain82 = "data-ukr.com" nocase
        $domain83 = "datagatellc.com" nocase
        $domain84 = "datagatewayglobal.com" nocase
        $domain85 = "datastoragecrypto.com" nocase
        $domain86 = "datawebhub.com" nocase
        $domain87 = "default-dns.online" nocase
        $domain88 = "definform.com" nocase
        $domain89 = "desgnspiration.net" nocase
        $domain90 = "deskactivitygm.com" nocase
        $domain91 = "directdocumentgate.com" nocase
        $domain92 = "directdocumentgateway.com" nocase
        $domain93 = "directexpressgateway.com" nocase
        $domain94 = "directstoragegate.com" nocase
        $domain95 = "disk-previewer.com" nocase
        $domain96 = "dns-cache.online" nocase
        $domain97 = "dns-challenge.com" nocase
        $domain98 = "dns-cookie.com" nocase
        $domain99 = "dns-mvd.ru" nocase
        $ip100 = "45.133.216.15"
        $ip101 = "89.19.211.240"
        $ip102 = "95.164.17.94"

    condition:
        any of them
}

rule APT_COLDWASTREL {
    meta:
        description = "Indicators associated with APT COLDWASTREL"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "account-api.cloudstorageservice.online" nocase
        $domain1 = "account-api.onlinestorageroute.space" nocase
        $domain2 = "account-api.protondrive.online" nocase
        $domain3 = "account.email-pm.me" nocase
        $domain4 = "account.onlinestorageroute.space" nocase
        $domain5 = "account.open-button.com" nocase
        $domain6 = "account.proton-drive.me" nocase
        $domain7 = "account.proton-service.services" nocase
        $domain8 = "account.proton-verify.me" nocase
        $domain9 = "account.proton.shared-urls.me" nocase
        $domain10 = "account.protondrive.cloud" nocase
        $domain11 = "account.protondrive.online" nocase
        $domain12 = "account.protondrive.onlinestorageroute.space" nocase
        $domain13 = "account.protondrive.services" nocase
        $domain14 = "account.secure-pm.me" nocase
        $domain15 = "account.service-pm.me" nocase
        $domain16 = "account.service-proton.com" nocase
        $domain17 = "account.service-proton.me" nocase
        $domain18 = "account.services-proton.me" nocase
        $domain19 = "accounts-proton.me" nocase
        $domain20 = "accounts.support-ukr.net" nocase
        $domain21 = "center-facebook.com" nocase
        $domain22 = "civic-synergy.online" nocase
        $domain23 = "cloudstorageservice.online" nocase
        $domain24 = "decryptor.me" nocase
        $domain25 = "desktop-facebook.com" nocase
        $domain26 = "document-decryption.me" nocase
        $domain27 = "drive-proton.com" nocase
        $domain28 = "drive.link-pm.me" nocase
        $domain29 = "drive.proton-verify.me" nocase
        $domain30 = "drive.proton.decryptor.me" nocase
        $domain31 = "drive.proton.filestorage.me" nocase
        $domain32 = "drive.proton.shared-urls.me" nocase
        $domain33 = "drive.secure-pm.me" nocase
        $domain34 = "drive.service-pm.me" nocase
        $domain35 = "drive.service-proton.me" nocase
        $domain36 = "driveproton.me" nocase
        $domain37 = "driveshare.me" nocase
        $domain38 = "edisk.support-ukr.net" nocase
        $domain39 = "email-pm.me" nocase
        $domain40 = "email-ukr.net" nocase
        $domain41 = "email.support-ukr.net" nocase
        $domain42 = "en-us.center-facebook.com" nocase
        $domain43 = "en-us.desktop-facebook.com" nocase
        $domain44 = "fb-me.com" nocase
        $domain45 = "fidh.tech" nocase
        $domain46 = "filestorage.me" nocase
        $domain47 = "fr-fr.center-facebook.com" nocase
        $domain48 = "h.maiils.com" nocase
        $domain49 = "link-pm.me" nocase
        $domain50 = "livecloudaccount.com" nocase
        $domain51 = "login.livecloudaccount.com" nocase
        $domain52 = "login.security-gm.com" nocase
        $domain53 = "login.support-gm.com" nocase
        $domain54 = "m.h.maiils.com" nocase
        $domain55 = "maiils.com" nocase
        $domain56 = "mail-api.onlinestorageroute.space" nocase
        $domain57 = "mail-api.protondrive.online" nocase
        $domain58 = "mail-ukr.net" nocase
        $domain59 = "mail.civic-synergy.online" nocase
        $domain60 = "mail.fidh.tech" nocase
        $domain61 = "mail.onetimeopportunity.store" nocase
        $domain62 = "mail.onlinestorageroute.space" nocase
        $domain63 = "mail.protondrive.online" nocase
        $domain64 = "mail.support-ukr.net" nocase
        $domain65 = "n.maiils.com" nocase
        $domain66 = "na.maiils.com" nocase
        $domain67 = "old.onlinestorageroute.space" nocase
        $domain68 = "old.protondrive.online" nocase
        $domain69 = "onetimeopportunity.store" nocase
        $domain70 = "online-facebook.com" nocase
        $domain71 = "onlinestorageroute.space" nocase
        $domain72 = "open-button.com" nocase
        $domain73 = "proton-drive.me" nocase
        $domain74 = "proton-service.services" nocase
        $domain75 = "proton-verify.me" nocase
        $domain76 = "proton.decryptor.me" nocase
        $domain77 = "proton.document-decryption.me" nocase
        $domain78 = "proton.driveshare.me" nocase
        $domain79 = "proton.filestorage.me" nocase
        $domain80 = "proton.shared-urls.me" nocase
        $domain81 = "protondrive.cloud" nocase
        $domain82 = "protondrive.me" nocase
        $domain83 = "protondrive.online" nocase
        $domain84 = "protondrive.onlinestorageroute.space" nocase
        $domain85 = "protondrive.services" nocase
        $domain86 = "reports.onlinestorageroute.space" nocase
        $domain87 = "reports.protondrive.online" nocase
        $domain88 = "ru-ru.center-facebook.com" nocase
        $domain89 = "ru-ru.desktop-facebook.com" nocase
        $domain90 = "secure-pm.me" nocase
        $domain91 = "secure.onlinestorageroute.space" nocase
        $domain92 = "secure.protondrive.online" nocase
        $domain93 = "security-gm.com" nocase
        $domain94 = "service-pm.me" nocase
        $domain95 = "service-proton.com" nocase
        $domain96 = "service-proton.me" nocase
        $domain97 = "service.link-pm.me" nocase
        $domain98 = "services-proton.me" nocase
        $domain99 = "shared-urls.me" nocase

    condition:
        any of them
}

rule APT_COMMENTCREW {
    meta:
        description = "Indicators associated with APT COMMENTCREW"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "08elec.purpledaily.com" nocase
        $domain1 = "09back.purpledaily.com" nocase
        $domain2 = "3ml.infosupports.com" nocase
        $domain3 = "3pma.firefoxupdata.com" nocase
        $domain4 = "4cback.hugesoft.org" nocase
        $domain5 = "7cback.hugesoft.org" nocase
        $domain6 = "911.cnnnewsdaily.com" nocase
        $domain7 = "a-ad.arrowservice.net" nocase
        $domain8 = "a-af.arrowservice.net" nocase
        $domain9 = "a-bne.arrowservice.net" nocase
        $domain10 = "a-co.purpledaily.com" nocase
        $domain11 = "a-dl.arrowservice.net" nocase
        $domain12 = "a-ec.businessconsults.net" nocase
        $domain13 = "a-ep.arrowservice.net" nocase
        $domain14 = "a-ex.arrowservice.net" nocase
        $domain15 = "a-fj.purpledaily.com" nocase
        $domain16 = "a-ga.purpledaily.com" nocase
        $domain17 = "a-gon.arrowservice.net" nocase
        $domain18 = "a-he.arrowservice.net" nocase
        $domain19 = "a-he.softsolutionbox.net" nocase
        $domain20 = "a-if.arrowservice.net" nocase
        $domain21 = "a-iho.arrowservice.net" nocase
        $domain22 = "a-ja.purpledaily.com" nocase
        $domain23 = "a-jsm.arrowservice.net" nocase
        $domain24 = "a-jsm.infobusinessus.org" nocase
        $domain25 = "a-ol.arrowservice.net" nocase
        $domain26 = "a-ov.businessconsults.net" nocase
        $domain27 = "a-pep.arrowservice.net" nocase
        $domain28 = "a-rdr.arrowservice.net" nocase
        $domain29 = "a-ri.comrepair.net" nocase
        $domain30 = "a-uac.arrowservice.net" nocase
        $domain31 = "a-un.purpledaily.com" nocase
        $domain32 = "a-za.arrowservice.net" nocase
        $domain33 = "a-za.businessconsults.net" nocase
        $domain34 = "a-zx.purpledaily.com" nocase
        $domain35 = "aam.businessconsults.net" nocase
        $domain36 = "aar.bigdepression.net" nocase
        $domain37 = "aarco.bigdepression.net" nocase
        $domain38 = "abs.businessconsults.net" nocase
        $domain39 = "acer.firefoxupdata.com" nocase
        $domain40 = "acli-mail.businessconsults.net" nocase
        $domain41 = "acu.businessconsults.net" nocase
        $domain42 = "adb.businessconsults.net" nocase
        $domain43 = "add.infosupports.com" nocase
        $domain44 = "addr.infosupports.com" nocase
        $domain45 = "adi002.hugesoft.org" nocase
        $domain46 = "admin.arrowservice.net" nocase
        $domain47 = "admin.datastorage01.org" nocase
        $domain48 = "admin.firefoxupdata.com" nocase
        $domain49 = "admin.softsolutionbox.net" nocase
        $domain50 = "adobe.firefoxupdata.com" nocase
        $domain51 = "ads.bpyoyo.com" nocase
        $domain52 = "adt.businessconsults.net" nocase
        $domain53 = "adt001.hugesoft.org" nocase
        $domain54 = "adt002.hugesoft.org" nocase
        $domain55 = "adtk.newsonet.net" nocase
        $domain56 = "adtkl.bigish.net" nocase
        $domain57 = "adtkl.gmailboxes.com" nocase
        $domain58 = "adtlk.bigish.net" nocase
        $domain59 = "advanbusiness.com" nocase
        $domain60 = "ae.firefoxupdata.com" nocase
        $domain61 = "aero.blackcake.net" nocase
        $domain62 = "aes.infosupports.com" nocase
        $domain63 = "af.arrowservice.net" nocase
        $domain64 = "afda.businessconsults.net" nocase
        $domain65 = "africa.mcafeepaying.com" nocase
        $domain66 = "africa.todayusa.org" nocase
        $domain67 = "africa.usabbs.org" nocase
        $domain68 = "africadb.arrowservice.net" nocase
        $domain69 = "afw.globalowa.com" nocase
        $domain70 = "agl.softsolutionbox.net" nocase
        $domain71 = "ago.businessconsults.net" nocase
        $domain72 = "aiic.arrowservice.net" nocase
        $domain73 = "aip.comrepair.net" nocase
        $domain74 = "airline.firefoxupdata.com" nocase
        $domain75 = "airplane.defenceonline.net" nocase
        $domain76 = "ait.busketball.com" nocase
        $domain77 = "ak47.infobusinessus.org" nocase
        $domain78 = "ak47.msnhome.org" nocase
        $domain79 = "alarm.arrowservice.net" nocase
        $domain80 = "alarm.infobusinessus.org" nocase
        $domain81 = "alcan.arrowservice.net" nocase
        $domain82 = "alion.businessconsults.net" nocase
        $domain83 = "alone.infosupports.com" nocase
        $domain84 = "amanda.firefoxupdata.com" nocase
        $domain85 = "amazingrm.com" nocase
        $domain86 = "amne.purpledaily.com" nocase
        $domain87 = "ams.busketball.com" nocase
        $domain88 = "amusement.firefoxupdata.com" nocase
        $domain89 = "analysis.firefoxupdata.com" nocase
        $domain90 = "anglo.arrowservice.net" nocase
        $domain91 = "anti.firefoxupdata.com" nocase
        $domain92 = "aol.arrowservice.net" nocase
        $domain93 = "aol.infobusinessus.org" nocase
        $domain94 = "aol.softsolutionbox.net" nocase
        $domain95 = "aoldaily.com" nocase
        $domain96 = "aolon1ine.com" nocase
        $domain97 = "aon.infobusinessus.org" nocase
        $domain98 = "apa.infosupports.com" nocase
        $domain99 = "apa.newsonet.net" nocase

    condition:
        any of them
}

rule APT_COPYKITTENS {
    meta:
        description = "Indicators associated with APT COPYKITTENS"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "alhadath.mobi" nocase
        $domain1 = "big-windowss.com" nocase
        $domain2 = "cacheupdate14.com" nocase
        $domain3 = "fbstatic-a.space" nocase
        $domain4 = "fbstatic-a.xyz" nocase
        $domain5 = "fbstatic-akamaihd.com" nocase
        $domain6 = "gmailtagmanager.com" nocase
        $domain7 = "haaretz-news.com" nocase
        $domain8 = "haaretz.link" nocase
        $domain9 = "heartax.info" nocase
        $domain10 = "kernel4windows.in" nocase
        $domain11 = "micro-windows.in" nocase
        $domain12 = "mswordupdate15.com" nocase
        $domain13 = "mswordupdate16.com" nocase
        $domain14 = "mswordupdate17.com" nocase
        $domain15 = "mywindows24.in" nocase
        $domain16 = "patch7-windows.com" nocase
        $domain17 = "patch8-windows.com" nocase
        $domain18 = "patchthiswindows.com" nocase
        $domain19 = "walla.link" nocase
        $domain20 = "wethearservice.com" nocase
        $domain21 = "wheatherserviceapi.info" nocase
        $domain22 = "windowkernel.com" nocase
        $domain23 = "windows-10patch.in" nocase
        $domain24 = "windows-drive20.com" nocase
        $domain25 = "windows-india.in" nocase
        $domain26 = "windows-kernel.in" nocase
        $domain27 = "windows-my50.com" nocase
        $domain28 = "windows24-kernel.in" nocase
        $domain29 = "windowskernel.in" nocase
        $domain30 = "windowskernel14.com" nocase
        $domain31 = "windowslayer.in" nocase
        $domain32 = "windowssup.in" nocase
        $domain33 = "windowsupup.com" nocase

    condition:
        any of them
}

rule APT_COSMICDUKE {
    meta:
        description = "Indicators associated with APT COSMICDUKE"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "dukehole.me" nocase

    condition:
        any of them
}

rule APT_CRIMSONCOLLECTIVE {
    meta:
        description = "Indicators associated with APT CRIMSONCOLLECTIVE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "crimson collective"

    strings:
        $ip0 = "195.201.175.210"
        $ip1 = "3.215.23.185"
        $ip2 = "3.215.23.185"
        $ip3 = "45.148.10.141"
        $ip4 = "45.148.10.141"
        $ip5 = "5.9.108.250"
        $ip6 = "5.9.108.250"

    condition:
        any of them
}

rule APT_CYBERAV3NGERS {
    meta:
        description = "Indicators associated with APT CYBERAV3NGERS"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "iocontrol"

    strings:
        $domain0 = "ocferda.com" nocase
        $domain1 = "tylarion867mino.com" nocase
        $domain2 = "uuokhhfsdlk.tylarion867mino.com" nocase
        $ip3 = "159.100.6.69"

    condition:
        any of them
}

rule APT_CYBERBIT {
    meta:
        description = "Indicators associated with APT CYBERBIT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "cd-media4u.com" nocase
        $domain1 = "diretube.co.uk" nocase
        $domain2 = "eastafro.net" nocase
        $domain3 = "flashpoint-ip.com" nocase
        $domain4 = "getadobeplayer.com" nocase
        $domain5 = "meskereme.net" nocase
        $domain6 = "nozonenet.com" nocase
        $domain7 = "pnv.vipnetwork.fr" nocase
        $domain8 = "pupki.co" nocase
        $domain9 = "rdhotel.uz" nocase
        $domain10 = "signalschool.net" nocase
        $domain11 = "thewhistleblowers.org" nocase
        $domain12 = "time-local.com" nocase
        $domain13 = "time-local.net" nocase
        $domain14 = "villepinte2017.dynu.net" nocase

    condition:
        any of them
}

rule APT_DALBIT {
    meta:
        description = "Indicators associated with APT DALBIT"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "m00nlight"

    strings:
        $domain0 = "aa.zxcss.com" nocase
        $domain1 = "ff.m00nlight.top" nocase
        $domain2 = "fk.m00nlight.top" nocase
        $domain3 = "lt.yxavkb.xyz" nocase
        $domain4 = "m00nlight.top" nocase
        $domain5 = "mod.m00nlight.top" nocase
        $domain6 = "sk1.m00nlight.top" nocase
        $domain7 = "yxavkb.xyz" nocase
        $domain8 = "zxcss.com" nocase
        $ip9 = "103.118.42.208"
        $ip10 = "175.24.32.228"
        $ip11 = "45.136.186.175"
        $ip12 = "45.93.28.103"
        $ip13 = "45.93.31.75"
        $ip14 = "91.217.139.117"
        $ip15 = "91.217.139.117"
        $ip16 = "91.217.139.117"

    condition:
        any of them
}

rule APT_DARKCARACAL {
    meta:
        description = "Indicators associated with APT DARKCARACAL"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "accountslogin.services" nocase
        $domain1 = "adobe-flashviewer.accountslogin.services" nocase
        $domain2 = "adobeair.net" nocase
        $domain3 = "adobeinstall.com" nocase
        $domain4 = "ancmax.com" nocase
        $domain5 = "arablivenews.com" nocase
        $domain6 = "arabpublisherslb.com" nocase
        $domain7 = "axroot.com" nocase
        $domain8 = "dropboxonline.com" nocase
        $domain9 = "ecowatchasia.com" nocase
        $domain10 = "etn9.com" nocase
        $domain11 = "fbtweets.net" nocase
        $domain12 = "globalmic.net" nocase
        $domain13 = "gsec.in" nocase
        $domain14 = "iceteapeach.com" nocase
        $domain15 = "jaysonj.no-ip.biz" nocase
        $domain16 = "kaliex.net" nocase
        $domain17 = "mangoco.net" nocase
        $domain18 = "mecodata.com" nocase
        $domain19 = "megadeb.com" nocase
        $domain20 = "nancyrazzouk.com" nocase
        $domain21 = "nvidiaupdate.com" nocase
        $domain22 = "opwalls.com" nocase
        $domain23 = "orange2015.net" nocase
        $domain24 = "paktest.ddns.net" nocase
        $domain25 = "planethdx.com" nocase
        $domain26 = "playermea.com" nocase
        $domain27 = "roxsoft.net" nocase
        $domain28 = "sabisint.com" nocase
        $domain29 = "secureandroid.info" nocase
        $domain30 = "skypeservice.no-ip.org" nocase
        $domain31 = "skypeupdate.com" nocase
        $domain32 = "tenoclock.net" nocase
        $domain33 = "tweetsfb.com" nocase
        $domain34 = "watermelon2017.com" nocase

    condition:
        any of them
}

rule APT_DARKHOTEL {
    meta:
        description = "Indicators associated with APT DARKHOTEL"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt06, apt-c-06, thinmon"

    strings:
        $domain0 = "100100011100.com" nocase
        $domain1 = "163pics.net" nocase
        $domain2 = "163services.com" nocase
        $domain3 = "42world.net" nocase
        $domain4 = "779999977.com" nocase
        $domain5 = "88dafa.biz" nocase
        $domain6 = "academyhouse.us" nocase
        $domain7 = "account163-mail.com" nocase
        $domain8 = "ackr.myvnc.com" nocase
        $domain9 = "acrobatup.com" nocase
        $domain10 = "adobearm.com" nocase
        $domain11 = "adobeplugs.net" nocase
        $domain12 = "adoberegister.flashserv.net" nocase
        $domain13 = "adobeupdates.com" nocase
        $domain14 = "albasrostga.com" nocase
        $domain15 = "alexa97.com" nocase
        $domain16 = "alphacranes.com" nocase
        $domain17 = "alphastros.com" nocase
        $domain18 = "amanity50.biz" nocase
        $domain19 = "anti-wars.org" nocase
        $domain20 = "appfreetools.com" nocase
        $domain21 = "apple-onlineservice.com" nocase
        $domain22 = "applyinfo.org" nocase
        $domain23 = "auto2115.icr38.net" nocase
        $domain24 = "auto2116.phpnet.us" nocase
        $domain25 = "auto24col.info" nocase
        $domain26 = "autobaba.net84.net" nocase
        $domain27 = "autoban.phpnet.us" nocase
        $domain28 = "autobicy.yaahosting.info" nocase
        $domain29 = "autobicycle.20x.cc" nocase
        $domain30 = "autobicycle.freehostking.com" nocase
        $domain31 = "autobicyyyyyy.50gigs.net" nocase
        $domain32 = "autoblank.oni.cc" nocase
        $domain33 = "autobrown.gofreeserve.com" nocase
        $domain34 = "autocargo.100gbfreehost.com" nocase
        $domain35 = "autocash.000php.com" nocase
        $domain36 = "autocashhh.hostmefree.org" nocase
        $domain37 = "autocaze.crabdance.com" nocase
        $domain38 = "autocheck.000page.com" nocase
        $domain39 = "autochecker.myftp.biz" nocase
        $domain40 = "autocracy.phpnet.us" nocase
        $domain41 = "autocrat.comuf.com" nocase
        $domain42 = "autodoor.freebyte.us" nocase
        $domain43 = "autof888com.20x.cc" nocase
        $domain44 = "autofseven.freei.me" nocase
        $domain45 = "autogeremys.com" nocase
        $domain46 = "autoinsurance.000space.com" nocase
        $domain47 = "autojob.whostas.com" nocase
        $domain48 = "autoken.scienceontheweb.net" nocase
        $domain49 = "autolace.twilightparadox.com" nocase
        $domain50 = "automachine.servequake.com" nocase
        $domain51 = "automatic.waldennetworks.com" nocase
        $domain52 = "automation.000a.biz" nocase
        $domain53 = "automation.icr38.net" nocase
        $domain54 = "automobile.000a.biz" nocase
        $domain55 = "automobile.200gigs.com" nocase
        $domain56 = "automobile.freei.me" nocase
        $domain57 = "automobile.it.cx" nocase
        $domain58 = "automobile.megabyet.net" nocase
        $domain59 = "automobile.x4host.eu" nocase
        $domain60 = "automobiles.strangled.net" nocase
        $domain61 = "automotive.20x.cc" nocase
        $domain62 = "autonomy.host22.com" nocase
        $domain63 = "autopapa.noads.biz" nocase
        $domain64 = "autopara.oliwy.net" nocase
        $domain65 = "autoparts.phpnet.us" nocase
        $domain66 = "autopatch.createandhost.com" nocase
        $domain67 = "autopatch.verwalten.ch" nocase
        $domain68 = "autophile.00free.net" nocase
        $domain69 = "autopilot.verwalten.ch" nocase
        $domain70 = "autoplant.byethost11.com" nocase
        $domain71 = "autopsy.createandhost.com" nocase
        $domain72 = "autoreviews.dyndns.info" nocase
        $domain73 = "autorico.ignorelist.com" nocase
        $domain74 = "autosadeo.000php.com" nocase
        $domain75 = "autosail.ns01.biz" nocase
        $domain76 = "autoshop.hostmefree.org" nocase
        $domain77 = "autostart.waldennetworks.com" nocase
        $domain78 = "autotest.byethost4.com" nocase
        $domain79 = "autotree.freebyte.us" nocase
        $domain80 = "autoup.eu.pn" nocase
        $domain81 = "autoupdafree.my5gigs.com" nocase
        $domain82 = "autoupdate.eg.vg" nocase
        $domain83 = "autoupdate.freehostia.com" nocase
        $domain84 = "autoupdate.megabyet.net" nocase
        $domain85 = "autoupdate.zoka.cc" nocase
        $domain86 = "autoupdatefree.freehostia.com" nocase
        $domain87 = "autoupdatefree.verwalten.ch" nocase
        $domain88 = "autoupdatefree.waldennetworks.com" nocase
        $domain89 = "autoupdatefree.zoka.cc" nocase
        $domain90 = "autoupdatefreee.my5gigs.com" nocase
        $domain91 = "autoupdates.5gigs.net" nocase
        $domain92 = "autoupdatfreeee.coolwwweb.com" nocase
        $domain93 = "autoupgrade.awardspace.biz" nocase
        $domain94 = "autovita.xtreemhost.com" nocase
        $domain95 = "autovonmanstein.x10.mx" nocase
        $domain96 = "autoworld.serveblog.net" nocase
        $domain97 = "autozone.000space.com" nocase
        $domain98 = "banilasky.com" nocase
        $domain99 = "begatrendsone.com" nocase
        $ip100 = "193.29.187.178"
        $ip101 = "193.29.187.178"
        $ip102 = "91.235.116.147"

    condition:
        any of them
}

rule APT_DARKHYDRUS {
    meta:
        description = "Indicators associated with APT DARKHYDRUS"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "0ffice.com" nocase
        $domain1 = "0ffice365.agency" nocase
        $domain2 = "0ffice365.life" nocase
        $domain3 = "0ffice365.services" nocase
        $domain4 = "0ffiice.com" nocase
        $domain5 = "0nedrive.agency" nocase
        $domain6 = "0utl00k.net" nocase
        $domain7 = "0utlook.accountant" nocase
        $domain8 = "0utlook.bid" nocase
        $domain9 = "akadns.services" nocase
        $domain10 = "akamai.agency" nocase
        $domain11 = "akamaiedge.live" nocase
        $domain12 = "akamaiedge.services" nocase
        $domain13 = "akamaized.live" nocase
        $domain14 = "akdns.live" nocase
        $domain15 = "allexa.net" nocase
        $domain16 = "anyconnect.stream" nocase
        $domain17 = "asimov-win-microsoft.services" nocase
        $domain18 = "asisdns.space" nocase
        $domain19 = "asismdnu.asisdns.space" nocase
        $domain20 = "azureedge.today" nocase
        $domain21 = "bigip.stream" nocase
        $domain22 = "brit.ns.cloudfronts.services" nocase
        $domain23 = "britns.akadns.live" nocase
        $domain24 = "britns.akadns.services" nocase
        $domain25 = "cisc0.net" nocase
        $domain26 = "citriix.net" nocase
        $domain27 = "cloudfronts.services" nocase
        $domain28 = "corewindows.agency" nocase
        $domain29 = "data-microsoft.services" nocase
        $domain30 = "dns.cloudfronts.services" nocase
        $domain31 = "edgekey.live" nocase
        $domain32 = "fortiweb.download" nocase
        $domain33 = "gogle.co" nocase
        $domain34 = "iecvlist-microsoft.live" nocase
        $domain35 = "kaspersky.host" nocase
        $domain36 = "kaspersky.science" nocase
        $domain37 = "maccaffe.com" nocase
        $domain38 = "microsoftlab.ir" nocase
        $domain39 = "microsoftonline.agency" nocase
        $domain40 = "microsoftonline.host" nocase
        $domain41 = "microsoftonline.services" nocase
        $domain42 = "microtik.stream" nocase
        $domain43 = "micrrosoft.net" nocase
        $domain44 = "msdncss.com" nocase
        $domain45 = "msdnscripts.com" nocase
        $domain46 = "ns1.microsoftlab.ir" nocase
        $domain47 = "ns102.kaspersky.host" nocase
        $domain48 = "ns103.kaspersky.host" nocase
        $domain49 = "ns2.akadns.live" nocase
        $domain50 = "ns2.akadns.services" nocase
        $domain51 = "ns2.microsoftlab.ir" nocase
        $domain52 = "nsatc.agency" nocase
        $domain53 = "onecs-live.services" nocase
        $domain54 = "onedrive.agency" nocase
        $domain55 = "owa365.bid" nocase
        $domain56 = "phicdn.world" nocase
        $domain57 = "sharepoint.agency" nocase
        $domain58 = "skydrive.agency" nocase
        $domain59 = "skydrive.services" nocase
        $domain60 = "symanteclive.download" nocase
        $domain61 = "t-msedge.world" nocase
        $domain62 = "tbs1.microsoftonline.services" nocase
        $domain63 = "tbs2.microsoftonline.services" nocase
        $domain64 = "trafficmanager.live" nocase
        $domain65 = "tvs1.trafficmanager.live" nocase
        $domain66 = "tvs2.trafficmanager.live" nocase
        $domain67 = "windowsdefender.win" nocase

    condition:
        any of them
}

rule APT_DARKPINK {
    meta:
        description = "Indicators associated with APT DARKPINK"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "chain.mycoinexplorer.com" nocase
        $domain1 = "mycoinexplorer.com" nocase
        $ip2 = "176.10.80.38"

    condition:
        any of them
}

rule APT_DARKRIVER {
    meta:
        description = "Indicators associated with APT DARKRIVER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "matadoor"

    strings:
        $domain0 = "aliveyelp.com" nocase
        $domain1 = "bestandgood.com" nocase
        $domain2 = "bettertimator.com" nocase
        $domain3 = "biowitsg.com" nocase
        $domain4 = "cakeduer.com" nocase
        $domain5 = "cameoonion.com" nocase
        $domain6 = "capetipper.com" nocase
        $domain7 = "casgone.com" nocase
        $domain8 = "cravefool.com" nocase
        $domain9 = "diemonge.com" nocase
        $domain10 = "e5afaya.com" nocase
        $domain11 = "editngo.com" nocase
        $domain12 = "eimvivb.com" nocase
        $domain13 = "endlessutie.com" nocase
        $domain14 = "fetchbring.com" nocase
        $domain15 = "fledscuba.com" nocase
        $domain16 = "flowuboy.com" nocase
        $domain17 = "futureinv-gp.com" nocase
        $domain18 = "ganjabuscoa.com" nocase
        $domain19 = "getmyecoin.com" nocase
        $domain20 = "iemcvv.com" nocase
        $domain21 = "interactive-guides.com" nocase
        $domain22 = "investsportss.com" nocase
        $domain23 = "ipodlasso.com" nocase
        $domain24 = "ismysoulmate.com" nocase
        $domain25 = "justlikeahummer.com" nocase
        $domain26 = "kixthstage.com" nocase
        $domain27 = "merudlement.com" nocase
        $domain28 = "metaversalk.com" nocase
        $domain29 = "mlaycld.com" nocase
        $domain30 = "moveandtry.com" nocase
        $domain31 = "myballmecg.com" nocase
        $domain32 = "nuttyhumid.com" nocase
        $domain33 = "offernewer.com" nocase
        $domain34 = "otopitele.com" nocase
        $domain35 = "outsidenursery.com" nocase
        $domain36 = "primventure.com" nocase
        $domain37 = "pursestout.com" nocase
        $domain38 = "reasonsalt.com" nocase
        $domain39 = "searching4soulmate.com" nocase
        $domain40 = "speclaurp.com" nocase
        $domain41 = "sureyuare.com" nocase
        $domain42 = "tarzoose.com" nocase
        $domain43 = "trendparlye.com" nocase
        $domain44 = "wemobiledauk.com" nocase
        $domain45 = "wharfgold.com" nocase
        $domain46 = "ww12.flowuboy.com" nocase
        $domain47 = "ww12.merudlement.com" nocase
        $domain48 = "ww12.offernewer.com" nocase
        $domain49 = "xdinzky.com" nocase
        $domain50 = "zeltactib.com" nocase

    condition:
        any of them
}

rule APT_DEADLYKISS {
    meta:
        description = "Indicators associated with APT DEADLYKISS"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "orionfile.com" nocase
        $domain1 = "tawaranmurah.com" nocase

    condition:
        any of them
}

rule APT_DEATHSTALKER {
    meta:
        description = "Indicators associated with APT DEATHSTALKER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "admex.org" nocase
        $domain1 = "adsoftpic.com" nocase
        $domain2 = "affijay.com" nocase
        $domain3 = "agagian.com" nocase
        $domain4 = "aidobe-update.com" nocase
        $domain5 = "allmedicalpro.com" nocase
        $domain6 = "allrivercenter.com" nocase
        $domain7 = "amazonappservice.com" nocase
        $domain8 = "amazoncld.com" nocase
        $domain9 = "amazoncontent.org" nocase
        $domain10 = "ammaze.org" nocase
        $domain11 = "amzbooks.org" nocase
        $domain12 = "amznapis.com" nocase
        $domain13 = "anyfoodappz.com" nocase
        $domain14 = "anypicsave.com" nocase
        $domain15 = "apidevops.org" nocase
        $domain16 = "apiygate.com" nocase
        $domain17 = "appcellor.com" nocase
        $domain18 = "apple-sdk.com" nocase
        $domain19 = "atomarket.org" nocase
        $domain20 = "audio-azure.com" nocase
        $domain21 = "azure-affiliate.com" nocase
        $domain22 = "azurecfd.com" nocase
        $domain23 = "azurecontents.com" nocase
        $domain24 = "azureservicesapi.com" nocase
        $domain25 = "bookfinder-ltd.com" nocase
        $domain26 = "borisjns.com" nocase
        $domain27 = "cargoargs.com" nocase
        $domain28 = "cashcores.org" nocase
        $domain29 = "check-avg.co" nocase
        $domain30 = "check-avg.com" nocase
        $domain31 = "cloud-appint.com" nocase
        $domain32 = "cloudappcer.com" nocase
        $domain33 = "cloudazureservices.com" nocase
        $domain34 = "cloudpdom.com" nocase
        $domain35 = "cloudreg-email.com" nocase
        $domain36 = "coreadvc.com" nocase
        $domain37 = "corstand.com" nocase
        $domain38 = "cosmoscld.com" nocase
        $domain39 = "covidaff.org" nocase
        $domain40 = "covidgov.org" nocase
        $domain41 = "covsafezone.com" nocase
        $domain42 = "dbcallog.com" nocase
        $domain43 = "dellscanhw.com" nocase
        $domain44 = "diamondncenter.biz" nocase
        $domain45 = "dnserviceapp.com" nocase
        $domain46 = "dnstotal.org" nocase
        $domain47 = "dogeofcoin.com" nocase
        $domain48 = "dustforms.com" nocase
        $domain49 = "earthviehuge.com" nocase
        $domain50 = "econfuss.com" nocase
        $domain51 = "edwardpof.com" nocase
        $domain52 = "eroclasp.com" nocase
        $domain53 = "esetupdater.com" nocase
        $domain54 = "ezteching.com" nocase
        $domain55 = "fastnetbrowsing.com" nocase
        $domain56 = "findmypcs.com" nocase
        $domain57 = "firedomez.com" nocase
        $domain58 = "flightpassist.com" nocase
        $domain59 = "flyingpackagetrack.com" nocase
        $domain60 = "footersig.pythonanywhere.com" nocase
        $domain61 = "forceground.co" nocase
        $domain62 = "futureggs.com" nocase
        $domain63 = "getappcloud.com" nocase
        $domain64 = "globalsignature.pythonanywhere.com" nocase
        $domain65 = "gofinancesolutions.com" nocase
        $domain66 = "govdefi.com" nocase
        $domain67 = "govtoffice.org" nocase
        $domain68 = "gratedomofrome.com" nocase
        $domain69 = "hostboxapp.com" nocase
        $domain70 = "hostedl.com" nocase
        $domain71 = "hpcloudlive.com" nocase
        $domain72 = "ihotel-deals.com" nocase
        $domain73 = "invgov.org" nocase
        $domain74 = "jarviservice.org" nocase
        $domain75 = "luccares.com" nocase
        $domain76 = "mailcloudservices.org" nocase
        $domain77 = "mailservice.pythonanywhere.com" nocase
        $domain78 = "mailservicenow.com" nocase
        $domain79 = "mailservices.pythonanywhere.com" nocase
        $domain80 = "mailsignature.pythonanywhere.com" nocase
        $domain81 = "mailsigning.pythonanywhere.com" nocase
        $domain82 = "mainsingular.com" nocase
        $domain83 = "mcafee-secd.com" nocase
        $domain84 = "mediqhealthcare.com" nocase
        $domain85 = "mevcsft.com" nocase
        $domain86 = "missft.com" nocase
        $domain87 = "msfastbrowse.com" nocase
        $domain88 = "msfsvctassist.com" nocase
        $domain89 = "msft-dev.com" nocase
        $domain90 = "msftapp.com" nocase
        $domain91 = "msftcd.com" nocase
        $domain92 = "msftcrs.com" nocase
        $domain93 = "msftinfo.com" nocase
        $domain94 = "msftmnvm.com" nocase
        $domain95 = "msftprint.com" nocase
        $domain96 = "msintsvc.com" nocase
        $domain97 = "mslogger.org" nocase
        $domain98 = "mullticon.com" nocase
        $domain99 = "multitrolli.com" nocase
        $ip100 = "176.223.165.196"
        $ip101 = "185.62.189.210"
        $ip102 = "87.120.254.100"
        $ip103 = "87.120.37.68"

    condition:
        any of them
}

rule APT_DESERTFALCON {
    meta:
        description = "Indicators associated with APT DESERTFALCON"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "abuhmaid.net" nocase
        $domain1 = "advtravel.info" nocase
        $domain2 = "ahmedfaiez.info" nocase
        $domain3 = "androcity.com" nocase
        $domain4 = "blogging-host.info" nocase
        $domain5 = "facebook-emoticons.bitblogoo.com" nocase
        $domain6 = "flushupate.com" nocase
        $domain7 = "flushupdate.com" nocase
        $domain8 = "fpupdate.info" nocase
        $domain9 = "ineltdriver.com" nocase
        $domain10 = "ineltdriver.info" nocase
        $domain11 = "iwork-sys.com" nocase
        $domain12 = "linkedim.in" nocase
        $domain13 = "linksis.info" nocase
        $domain14 = "liptona.net" nocase
        $domain15 = "mediahitech.com" nocase
        $domain16 = "mediahitech.info" nocase
        $domain17 = "mixedwork.com" nocase
        $domain18 = "nauss-lab.com" nocase
        $domain19 = "nice-mobiles.com" nocase
        $domain20 = "plmedgroup.com" nocase
        $domain21 = "pstcmedia.com" nocase
        $domain22 = "tvgate.rocks" nocase

    condition:
        any of them
}

rule APT_DNSPIONAGE {
    meta:
        description = "Indicators associated with APT DNSPIONAGE"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "0ffice36o.com" nocase
        $domain1 = "18-79-t.net" nocase
        $domain2 = "1qhd6v.xyz" nocase
        $domain3 = "4f-okdsvv.com" nocase
        $domain4 = "5-9idk-gug7-k7.com" nocase
        $domain5 = "52-ck29jr.com" nocase
        $domain6 = "5z-hyq-g.net" nocase
        $domain7 = "78p3-zgs-g-mc-u.com" nocase
        $domain8 = "8f-mxh6-hupgd-dy.com" nocase
        $domain9 = "8faf-rngtax.com" nocase
        $domain10 = "a87-sun0r1w.com" nocase
        $domain11 = "ac5e1f-fd2ph.com" nocase
        $domain12 = "acyjob.tokyo" nocase
        $domain13 = "adchum.tokyo" nocase
        $domain14 = "adzwrq.tokyo" nocase
        $domain15 = "akgxtu.tokyo" nocase
        $domain16 = "aletko.tokyo" nocase
        $domain17 = "am41-pm24ea.com" nocase
        $domain18 = "amb29l1v3re.com" nocase
        $domain19 = "ami10t-e37n.com" nocase
        $domain20 = "an87-24pen1d.com" nocase
        $domain21 = "and58-65kio.com" nocase
        $domain22 = "apply33547.com" nocase
        $domain23 = "ar5-chj-n-22d.com" nocase
        $domain24 = "as93-attack1.com" nocase
        $domain25 = "aso5fr-gre4.com" nocase
        $domain26 = "au.imonju.net" nocase
        $domain27 = "b5mjjc8s.com" nocase
        $domain28 = "baebod.tokyo" nocase
        $domain29 = "ban09-4w1as.com" nocase
        $domain30 = "batdongsan.dcsvnqvmn.com" nocase
        $domain31 = "baw2u-y6rsxf.com" nocase
        $domain32 = "bed52-town1.com" nocase
        $domain33 = "big429-7ten.com" nocase
        $domain34 = "bing0017-s4e.com" nocase
        $domain35 = "bing04-5ea1.com" nocase
        $domain36 = "bm-8qkc8w.com" nocase
        $domain37 = "bnv521-send4.com" nocase
        $domain38 = "boat-19830214yh.com" nocase
        $domain39 = "boceuz.tokyo" nocase
        $domain40 = "boundhereafter.com" nocase
        $domain41 = "bpugoc.tokyo" nocase
        $domain42 = "bqufsuqj.com" nocase
        $domain43 = "buffdrops.com" nocase
        $domain44 = "bvnc5418-4s.com" nocase
        $domain45 = "c02bf1r-kjre.com" nocase
        $domain46 = "c7ykg-0sd5w.com" nocase
        $domain47 = "cd-7rr-hgj.net" nocase
        $domain48 = "cg58-6dr4wa.com" nocase
        $domain49 = "chai58-mnew.com" nocase
        $domain50 = "check.onedrvdn.co" nocase
        $domain51 = "chi12-63in7m.com" nocase
        $domain52 = "cm.appupdatemoremagic.com" nocase
        $domain53 = "cont24-57hin.com" nocase
        $domain54 = "crimeprocession.com" nocase
        $domain55 = "crtfugrl.com" nocase
        $domain56 = "cxevgfdy.com" nocase
        $domain57 = "d-wl-kk.net" nocase
        $domain58 = "d56gr-n2syp.xyz" nocase
        $domain59 = "dalat.dalat.dulichovietnam.net" nocase
        $domain60 = "dalat.dulichovietnam.net" nocase
        $domain61 = "dan02-opl1h.com" nocase
        $domain62 = "dan07oe0ch2f.com" nocase
        $domain63 = "dan104.com" nocase
        $domain64 = "dan32-ty65d.com" nocase
        $domain65 = "dbfrqm.tokyo" nocase
        $domain66 = "deliver-avenir.com" nocase
        $domain67 = "den-85gh40ik.com" nocase
        $domain68 = "developermisguided.email" nocase
        $domain69 = "devzxm.tokyo" nocase
        $domain70 = "dgywxfhuuy.com" nocase
        $domain71 = "dhs4oms-plas.com" nocase
        $domain72 = "dice-71ieoq.com" nocase
        $domain73 = "dick06-a4e6o.com" nocase
        $domain74 = "displayexploitation.com" nocase
        $domain75 = "download.showprice.xyz" nocase
        $domain76 = "dsykub.tokyo" nocase
        $domain77 = "dwwkvf.tokyo" nocase
        $domain78 = "e9dzrisph.com" nocase
        $domain79 = "eden52-74ea.com" nocase
        $domain80 = "edjkpz.tokyo" nocase
        $domain81 = "edli501d-eaq.com" nocase
        $domain82 = "eec-channel.com" nocase
        $domain83 = "elcend.tokyo" nocase
        $domain84 = "ell90-deep1w.com" nocase
        $domain85 = "end09-r6s3x.com" nocase
        $domain86 = "end87q.com" nocase
        $domain87 = "eri05-63h4w.com" nocase
        $domain88 = "eri25-d044g.com" nocase
        $domain89 = "error.a87-sun0r1w.com" nocase
        $domain90 = "error.amb29l1v3re.com" nocase
        $domain91 = "error.bing0017-s4e.com" nocase
        $domain92 = "error.boat-19830214yh.com" nocase
        $domain93 = "error.chai58-mnew.com" nocase
        $domain94 = "error.dan07oe0ch2f.com" nocase
        $domain95 = "error.dan104.com" nocase
        $domain96 = "error.dice-71ieoq.com" nocase
        $domain97 = "error.eden52-74ea.com" nocase
        $domain98 = "error.end87q.com" nocase
        $domain99 = "error.get814sf1qz.com" nocase

    condition:
        any of them
}

rule APT_DOCLESS {
    meta:
        description = "Indicators associated with APT DOCLESS"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "144.202.54.86"

    condition:
        any of them
}

rule APT_DOMESTICKITTEN {
    meta:
        description = "Indicators associated with APT DOMESTICKITTEN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-50"

    strings:
        $domain0 = "androidsecurityupdate.com" nocase
        $domain1 = "androidsystemsupdate.com" nocase
        $domain2 = "androidsystemswebview.com" nocase
        $domain3 = "appsoftupdate.com" nocase
        $domain4 = "arzdigitals.com" nocase
        $domain5 = "firmwaresystemupdate.com" nocase
        $domain6 = "georgethompson.space" nocase
        $domain7 = "googleassisstants.com" nocase
        $domain8 = "googleservicesforar.com" nocase
        $domain9 = "googleupdateservicese.com" nocase
        $domain10 = "googlextabv.com" nocase
        $domain11 = "lohefeshordeh.net" nocase
        $domain12 = "newportschoolupdateserver.com" nocase
        $domain13 = "ns1.googleassisstants.com" nocase
        $domain14 = "ns2.googleassisstants.com" nocase
        $domain15 = "padre914.com" nocase
        $domain16 = "ronaldlubbers.site" nocase
        $domain17 = "sarayemaghale.hami24.net" nocase
        $domain18 = "stevenwentz.com" nocase
        $domain19 = "systemdriverupdate.com" nocase
        $domain20 = "ychatonline.net" nocase
        $domain21 = "ydownyload.net" nocase
        $domain22 = "ynewnow.net" nocase
        $ip23 = "198.50.220.44"

    condition:
        any of them
}

rule APT_DONOT {
    meta:
        description = "Indicators associated with APT DONOT"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-35, donot, stealjob"

    strings:
        $domain0 = "162-33-178-135.cprapid.com" nocase
        $domain1 = "abletalk.info" nocase
        $domain2 = "abodeupdater.com" nocase
        $domain3 = "account-sign-in-security.ga" nocase
        $domain4 = "account-update-com.tk" nocase
        $domain5 = "account-updates-team.ga" nocase
        $domain6 = "accounts.googel.email" nocase
        $domain7 = "adjusteble.info" nocase
        $domain8 = "advancedmapsone.com" nocase
        $domain9 = "advancesearch.xyz" nocase
        $domain10 = "afd-gov-bd.gq" nocase
        $domain11 = "aioupdates.buzz" nocase
        $domain12 = "akamaifast.club" nocase
        $domain13 = "akamaihub.stream" nocase
        $domain14 = "alter.drivethrough.top" nocase
        $domain15 = "altzserberin.info" nocase
        $domain16 = "amazon-books-gifts.com" nocase
        $domain17 = "aoc.sessions4life.pw" nocase
        $domain18 = "apifile.xyz" nocase
        $domain19 = "apkfreeware.xyz" nocase
        $domain20 = "apkv6.endurecif.top" nocase
        $domain21 = "aplcompin.site" nocase
        $domain22 = "aplinvest.site" nocase
        $domain23 = "aplusgroup.online" nocase
        $domain24 = "app-palace.live" nocase
        $domain25 = "app-view-support.club" nocase
        $domain26 = "appie.host" nocase
        $domain27 = "appnsure.com" nocase
        $domain28 = "apps.privatechat.life" nocase
        $domain29 = "appservices.info" nocase
        $domain30 = "appshare.buzz" nocase
        $domain31 = "appshares.buzz" nocase
        $domain32 = "appsharing.buzz" nocase
        $domain33 = "appsharinggo.buzz" nocase
        $domain34 = "appshazing.buzz" nocase
        $domain35 = "appsservicess.buzz" nocase
        $domain36 = "appsservicess.info" nocase
        $domain37 = "appsshares.buzz" nocase
        $domain38 = "appstringfy.xyz" nocase
        $domain39 = "appsupports.info" nocase
        $domain40 = "appview.buzz" nocase
        $domain41 = "appzserv.info" nocase
        $domain42 = "azure.mglassservice.com" nocase
        $domain43 = "backup.latestsyn.xyz" nocase
        $domain44 = "backuplogs.xyz" nocase
        $domain45 = "baf-mil-bd.tk" nocase
        $domain46 = "bakedcakes.online" nocase
        $domain47 = "balancelogs.buzz" nocase
        $domain48 = "beachupdates.live" nocase
        $domain49 = "beetelson.xyz" nocase
        $domain50 = "best.tasterschoice.shop" nocase
        $domain51 = "bigdata.akamaihub.stream" nocase
        $domain52 = "bijoyshare.buzz" nocase
        $domain53 = "bike.drivethrough.top" nocase
        $domain54 = "birdperson.xyz" nocase
        $domain55 = "bismi.club" nocase
        $domain56 = "bitdo.xyz" nocase
        $domain57 = "biteupdates.live" nocase
        $domain58 = "biteupdates.site" nocase
        $domain59 = "bitiy.info" nocase
        $domain60 = "blakesleepa.business" nocase
        $domain61 = "blinkedeye.top" nocase
        $domain62 = "bloggerboy.buzz" nocase
        $domain63 = "blogs.box4box.online" nocase
        $domain64 = "blogs.firelive.pics" nocase
        $domain65 = "blogs.libraryutilitis.live" nocase
        $domain66 = "blogs.pakdw.live" nocase
        $domain67 = "blogs.tourseasons.xyz" nocase
        $domain68 = "blogs.updatepc.shop" nocase
        $domain69 = "blue.retroservices.buzz" nocase
        $domain70 = "blufflogz.info" nocase
        $domain71 = "bookservices.xyz" nocase
        $domain72 = "boostgridz.info" nocase
        $domain73 = "box4box.online" nocase
        $domain74 = "breatleytaker.buzz" nocase
        $domain75 = "briefdeal.buzz" nocase
        $domain76 = "brightnew.xyz" nocase
        $domain77 = "brilient.buzz" nocase
        $domain78 = "brityservice.info" nocase
        $domain79 = "brokensences.info" nocase
        $domain80 = "bsodsupport.icu" nocase
        $domain81 = "bulk.fun" nocase
        $domain82 = "bulkquantity.info" nocase
        $domain83 = "bunzpowe.info" nocase
        $domain84 = "burningforests.com" nocase
        $domain85 = "calvya.xyz" nocase
        $domain86 = "caplinks.buzz" nocase
        $domain87 = "captainamericass.top" nocase
        $domain88 = "car.drivethrough.top" nocase
        $domain89 = "cardlogical.info" nocase
        $domain90 = "carefile.icu" nocase
        $domain91 = "certific-activation.info" nocase
        $domain92 = "chandhor.top" nocase
        $domain93 = "chartsbezorgd.info" nocase
        $domain94 = "chat.zaqxswcdevfrbgtnhymjukilop.online" nocase
        $domain95 = "chaterbox.org" nocase
        $domain96 = "chatinsec.live" nocase
        $domain97 = "cheaper.buzz" nocase
        $domain98 = "cheaplate.info" nocase
        $domain99 = "checkbox.gq" nocase
        $ip100 = "131.153.22.218"
        $ip101 = "135.181.198.146"
        $ip102 = "139.180.135.59"
        $ip103 = "142.93.12.211"
        $ip104 = "151.236.11.222"
        $ip105 = "151.236.18.167"
        $ip106 = "162.33.177.183"
        $ip107 = "162.33.178.242"
        $ip108 = "162.33.178.3"
        $ip109 = "162.33.178.85"
        $ip110 = "162.33.179.171"
        $ip111 = "162.33.179.198"
        $ip112 = "162.33.179.238"
        $ip113 = "162.33.179.32"
        $ip114 = "164.68.108.22"
        $ip115 = "164.68.108.22"
        $ip116 = "167.99.130.191"
        $ip117 = "167.99.190.44"
        $ip118 = "178.63.172.2"
        $ip119 = "178.63.172.6"
        $ip120 = "185.195.64.251"
        $ip121 = "185.224.83.16"
        $ip122 = "193.149.176.226"
        $ip123 = "193.149.176.226"
        $ip124 = "193.149.176.237"
        $ip125 = "193.149.176.65"
        $ip126 = "193.149.176.65"
        $ip127 = "195.85.115.143"
        $ip128 = "206.188.197.34"
        $ip129 = "206.188.197.34"
        $ip130 = "206.188.197.53"
        $ip131 = "206.188.197.82"
        $ip132 = "23.83.133.141"
        $ip133 = "37.220.31.59"
        $ip134 = "38.180.106.242"
        $ip135 = "42.192.53.5"
        $ip136 = "45.138.172.7"
        $ip137 = "45.147.229.93"
        $ip138 = "45.61.136.15"
        $ip139 = "45.61.136.203"
        $ip140 = "45.61.136.231"
        $ip141 = "45.61.136.80"
        $ip142 = "45.61.137.213"
        $ip143 = "45.90.217.219"
        $ip144 = "66.23.225.108"
        $ip145 = "72.5.43.148"
        $ip146 = "88.150.227.96"

    condition:
        any of them
}

rule APT_DOWNEX {
    meta:
        description = "Indicators associated with APT DOWNEX"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "BlackGuard, cherryspy, hatvibe"

    strings:
        $domain0 = "background-services.net" nocase
        $domain1 = "diagnostic-resolver.com" nocase
        $domain2 = "download-resourses.info" nocase
        $domain3 = "energieecoinnov.info" nocase
        $domain4 = "energieecotech.info" nocase
        $domain5 = "enrollmentdm.com" nocase
        $domain6 = "lookup.ink" nocase
        $domain7 = "ms-webdav-miniredir.com" nocase
        $domain8 = "net-certificate.services" nocase
        $domain9 = "trust-certificate.net" nocase
        $ip10 = "38.180.207.137"

    condition:
        any of them
}

rule APT_DRAGONOK {
    meta:
        description = "Indicators associated with APT DRAGONOK"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bbs.donkeyhaws.info" nocase
        $domain1 = "biosnews.info" nocase
        $domain2 = "busserh.mancely.com" nocase
        $domain3 = "donkeyhaws.info" nocase
        $domain4 = "ghostale.com" nocase
        $domain5 = "http.donkeyhaws.info" nocase
        $domain6 = "https.osakaintec.com" nocase
        $domain7 = "jpaols.com" nocase
        $domain8 = "moafee.com" nocase
        $domain9 = "ndbssh.com" nocase
        $domain10 = "php.marbletemps.com" nocase
        $domain11 = "pktmedia.com" nocase
        $domain12 = "skyppee.com" nocase
        $domain13 = "ycbackap.com" nocase

    condition:
        any of them
}

rule APT_DRIFTINGCLOUD {
    meta:
        description = "Indicators associated with APT DRIFTINGCLOUD"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "akamprod.com" nocase
        $domain1 = "googleanalytics.proxydns.com" nocase
        $domain2 = "servusers.com" nocase
        $domain3 = "u2d.servusers.com" nocase

    condition:
        any of them
}

rule APT_DUKE {
    meta:
        description = "Indicators associated with APT DUKE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "APT29, Cozy Bear, The Dukes"

    strings:
        $domain0 = "1597ebba.info.gtjas.site" nocase
        $domain1 = "3bcc1bba.info.gtjas.site" nocase
        $domain2 = "4freerussia.cloud" nocase
        $domain3 = "74d6b7b2.app.giftbox4u.com" nocase
        $domain4 = "7c291bbe.info.gtjas.site" nocase
        $domain5 = "acciaio.com.br" nocase
        $domain6 = "accounts-google.online" nocase
        $domain7 = "actualcombine.com" nocase
        $domain8 = "adm.govua.cloud" nocase
        $domain9 = "admin-ch.cloud" nocase
        $domain10 = "aeinc.solutions" nocase
        $domain11 = "ahmed-ms.online" nocase
        $domain12 = "airtravelabroad.com" nocase
        $domain13 = "aka-ms.cloud" nocase
        $domain14 = "albrightstonebridge.cloud" nocase
        $domain15 = "amazonmeeting.cloud" nocase
        $domain16 = "amazonsolutions.cloud" nocase
        $domain17 = "americanprogress.cloud" nocase
        $domain18 = "ap-northeast-1-aws.s3-ua.cloud" nocase
        $domain19 = "ap-northeast-1-aws.ukrainesec.cloud" nocase
        $domain20 = "aspeninstitute.cloud" nocase
        $domain21 = "asucloud.us" nocase
        $domain22 = "avis-google.online" nocase
        $domain23 = "aws-app.online" nocase
        $domain24 = "aws-atshop.online" nocase
        $domain25 = "aws-cert.online" nocase
        $domain26 = "aws-cloud.online" nocase
        $domain27 = "aws-cloud.tech" nocase
        $domain28 = "aws-data.cloud" nocase
        $domain29 = "aws-devops.site" nocase
        $domain30 = "aws-exam.online" nocase
        $domain31 = "aws-il.cloud" nocase
        $domain32 = "aws-join.cloud" nocase
        $domain33 = "aws-meet.cloud" nocase
        $domain34 = "aws-meetings.cloud" nocase
        $domain35 = "aws-ms.cloud" nocase
        $domain36 = "aws-my.online" nocase
        $domain37 = "aws-online.cloud" nocase
        $domain38 = "aws-platform.cloud" nocase
        $domain39 = "aws-s3.cloud" nocase
        $domain40 = "aws-sagyo.site" nocase
        $domain41 = "aws-sample.online" nocase
        $domain42 = "aws-secure.cloud" nocase
        $domain43 = "aws-talib.online" nocase
        $domain44 = "aws-ukraine.cloud" nocase
        $domain45 = "aws-yamada.site" nocase
        $domain46 = "awsmeet.cloud" nocase
        $domain47 = "awsmeetings.online" nocase
        $domain48 = "awsplatform.online" nocase
        $domain49 = "awsprotect.online" nocase
        $domain50 = "backupify.cloud" nocase
        $domain51 = "bakenhof.com" nocase
        $domain52 = "bandabonga.fr" nocase
        $domain53 = "barracuda.solutions" nocase
        $domain54 = "beijingnewsblog.net" nocase
        $domain55 = "bravecup.com" nocase
        $domain56 = "bringthenoiseappnew.s3.amazonaws.com" nocase
        $domain57 = "brookings.cloud" nocase
        $domain58 = "bund-de.cloud" nocase
        $domain59 = "busseylawoffice.com" nocase
        $domain60 = "c-r.services" nocase
        $domain61 = "ca-central-1.awsplatform.online" nocase
        $domain62 = "ca-central-1.gov-ua.cloud" nocase
        $domain63 = "ca-central-1.ua-gov.cloud" nocase
        $domain64 = "ca-west-1.aws-ukraine.cloud" nocase
        $domain65 = "ca-west-1.mfa-gov.cloud" nocase
        $domain66 = "ca-west-1.ukrtelecom.cloud" nocase
        $domain67 = "cabemanis-ms.online" nocase
        $domain68 = "caci.solutions" nocase
        $domain69 = "cadastros-google.online" nocase
        $domain70 = "capgemini.services" nocase
        $domain71 = "ceip.cloud" nocase
        $domain72 = "central-2-aws.ua-aws.army" nocase
        $domain73 = "central-2-aws.ua-mil.cloud" nocase
        $domain74 = "central-2-aws.ua-sec.cloud" nocase
        $domain75 = "central-2-aws.ukrainesec.cloud" nocase
        $domain76 = "central-2-aws.ukrtelecom.cloud" nocase
        $domain77 = "cepa.solutions" nocase
        $domain78 = "cer.zone" nocase
        $domain79 = "ceycarb.com" nocase
        $domain80 = "cfr-aws.cloud" nocase
        $domain81 = "citoc.cloud" nocase
        $domain82 = "clari.cloud" nocase
        $domain83 = "clearancejobs.cloud" nocase
        $domain84 = "cloudflare.redirectpartners.com" nocase
        $domain85 = "cnas.zone" nocase
        $domain86 = "coachandcook.at" nocase
        $domain87 = "cod-ms.online" nocase
        $domain88 = "com-s3.cloud" nocase
        $domain89 = "commerce-mil.online" nocase
        $domain90 = "console-google.cloud" nocase
        $domain91 = "content.pcmsar.net" nocase
        $domain92 = "cribl-gov.cloud" nocase
        $domain93 = "crisisgroup.services" nocase
        $domain94 = "csbaonline.cloud" nocase
        $domain95 = "csu-gov.cloud" nocase
        $domain96 = "ctu-gov.cloud" nocase
        $domain97 = "cwinc.cloud" nocase
        $domain98 = "d1d66buv7blf1z.cloudfront.net" nocase
        $domain99 = "d287-206-123-149-139.ngrok-free.app" nocase
        $ip100 = "103.216.221.18"
        $ip101 = "103.253.41.102"
        $ip102 = "103.76.128.34"
        $ip103 = "111.90.150.140"
        $ip104 = "141.98.212.55"
        $ip105 = "141.98.212.55"
        $ip106 = "185.243.99.17"
        $ip107 = "209.58.186.196"
        $ip108 = "45.91.93.89"

    condition:
        any of them
}

rule APT_DUNEQUIXOTE {
    meta:
        description = "Indicators associated with APT DUNEQUIXOTE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "CR4T"

    strings:
        $domain0 = "commonline.space" nocase
        $domain1 = "e1awq1lp.commonline.space" nocase
        $domain2 = "g1sea23g.commonline.space" nocase
        $domain3 = "mc.commonline.space" nocase
        $domain4 = "service.userfeedsync.com" nocase
        $domain5 = "telemetry.commonline.space" nocase
        $domain6 = "telemetry.userfeedsync.com" nocase
        $domain7 = "tg1sea23g.commonline.space" nocase
        $domain8 = "userfeedsync.com" nocase

    condition:
        any of them
}

rule APT_DUSTSPECTER {
    meta:
        description = "Indicators associated with APT DUSTSPECTER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "splitdrop, twintask, twintalk"

    strings:
        $domain0 = "207-e-walter.xyz" nocase
        $domain1 = "afterworld.store" nocase
        $domain2 = "anythingshere.shop" nocase
        $domain3 = "cside.site" nocase
        $domain4 = "cywofio2.pro" nocase
        $domain5 = "digitaleconomy.lol" nocase
        $domain6 = "digitallcomunity.xyz" nocase
        $domain7 = "fashionmodels.site" nocase
        $domain8 = "findbesthotels.info" nocase
        $domain9 = "footballclub.sbs" nocase
        $domain10 = "footballfans.asia" nocase
        $domain11 = "formacja.info" nocase
        $domain12 = "garbagecollector.site" nocase
        $domain13 = "girlsbags.shop" nocase
        $domain14 = "justweb.click" nocase
        $domain15 = "lecturegenieltd.pro" nocase
        $domain16 = "luckywavez.shop" nocase
        $domain17 = "mancpr.icu" nocase
        $domain18 = "meetingapp.site" nocase
        $domain19 = "menclub.lt" nocase
        $domain20 = "musiclivetrack.website" nocase
        $domain21 = "ntcx.pro" nocase
        $domain22 = "onlinepettools.shop" nocase
        $domain23 = "parct.tech" nocase
        $domain24 = "phoneaccessory.site" nocase
        $domain25 = "programmingcourse.site" nocase
        $domain26 = "retseptik.info" nocase
        $domain27 = "sportscarshop.lol" nocase
        $domain28 = "steelweight.mobi" nocase
        $domain29 = "stone110.store" nocase
        $domain30 = "test.tender.pro" nocase
        $domain31 = "test.xn--d1abb4arh.xn--p1ai" nocase
        $domain32 = "testold.tender.pro" nocase
        $domain33 = "web14.info" nocase
        $domain34 = "web27.info" nocase
        $domain35 = "wehakaa2.pro" nocase
        $ip36 = "185.76.79.125"
        $ip37 = "38.180.239.161"
        $ip38 = "83.172.159.180"
        $ip39 = "92.243.65.243"

    condition:
        any of them
}

rule APT_DUSTSQUAD {
    meta:
        description = "Indicators associated with APT DUSTSQUAD"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "Dustsquad, Octopus, Nomadic Octopus"

    strings:
        $domain0 = "blondehairman.com" nocase
        $domain1 = "certificatesshop.com" nocase
        $domain2 = "cookiesqueen.com" nocase
        $domain3 = "desperados20.es" nocase
        $domain4 = "footcoinball.com" nocase
        $domain5 = "giftfromspace.com" nocase
        $domain6 = "hovnanflovers.com" nocase
        $domain7 = "humorpics.download" nocase
        $domain8 = "islandsnake.com" nocase
        $domain9 = "latecafe.in" nocase
        $domain10 = "lovingearthy.com" nocase
        $domain11 = "mikohanzer.website" nocase
        $domain12 = "poisonfight.com" nocase
        $domain13 = "porenticofacts.com" nocase
        $domain14 = "prom3.biz.ua" nocase

    condition:
        any of them
}

rule APT_EARTHBERBEROKA {
    meta:
        description = "Indicators associated with APT EARTHBERBEROKA"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "1.googie.ph" nocase
        $domain1 = "12371829hkdanm.fbi.am" nocase
        $domain2 = "1qw6etagydbn2peifj8hf.fbi.am" nocase
        $domain3 = "2.googie.ph" nocase
        $domain4 = "3.googie.ph" nocase
        $domain5 = "adobe-flash.wiki" nocase
        $domain6 = "adobe.name" nocase
        $domain7 = "agph.ivi66.net" nocase
        $domain8 = "bos.github.wiki" nocase
        $domain9 = "caonimade.11i.me" nocase
        $domain10 = "d.github.wiki" nocase
        $domain11 = "darknet.rootkit.tools" nocase
        $domain12 = "darwin.github.wiki" nocase
        $domain13 = "download.mircrosoftscoulds.com" nocase
        $domain14 = "dust.github.wiki" nocase
        $domain15 = "exmail.googie.com.ph" nocase
        $domain16 = "fbi.fuckbc.com" nocase
        $domain17 = "flash.wy886066.com" nocase
        $domain18 = "fuckbc.com" nocase
        $domain19 = "fuckeryoumm.nmb.bet" nocase
        $domain20 = "fuckyou.fbi.am" nocase
        $domain21 = "gb.googie.ph" nocase
        $domain22 = "github.wiki" nocase
        $domain23 = "googie.com.ph" nocase
        $domain24 = "googie.ph" nocase
        $domain25 = "helloword.11i.me" nocase
        $domain26 = "helloword.daj8.me" nocase
        $domain27 = "hk.whoamis.info" nocase
        $domain28 = "hkdust.github.wiki" nocase
        $domain29 = "huaidan.fbi.am" nocase
        $domain30 = "ivi66.net" nocase
        $domain31 = "linux.daj8.me" nocase
        $domain32 = "linux.daji8.me" nocase
        $domain33 = "linux.shopingchina.net" nocase
        $domain34 = "linux.wy01.com" nocase
        $domain35 = "linux.wy01.vip" nocase
        $domain36 = "linux1.shopingchina.net" nocase
        $domain37 = "linux2.shopingchina.net" nocase
        $domain38 = "list.whoamis.info" nocase
        $domain39 = "localhost.11i.me" nocase
        $domain40 = "mircrosoftscoulds.com" nocase
        $domain41 = "mmimdown.oss-cn-hongkong.aliyuncs.com" nocase
        $domain42 = "rc.dajuw.com" nocase
        $domain43 = "rootkit.tools" nocase
        $domain44 = "shopingchina.net" nocase
        $domain45 = "steam.dajuw.com" nocase
        $domain46 = "test.mircrosoftscoulds.com" nocase
        $domain47 = "tools.daji8.me" nocase
        $domain48 = "update.adobe.wiki" nocase
        $domain49 = "win.googie.ph" nocase
        $domain50 = "wmgnews.daji8.me" nocase
        $domain51 = "wps.daj8.me" nocase
        $domain52 = "wpsup.daj8.me" nocase
        $domain53 = "wy886066.com" nocase
        $domain54 = "yabo.googie.ph" nocase
        $ip55 = "103.43.18.71"
        $ip56 = "167.179.95.191"
        $ip57 = "45.76.199.119"

    condition:
        any of them
}

rule APT_EARTHESTRIES {
    meta:
        description = "Indicators associated with APT EARTHESTRIES"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "hemigate, trillclient, zingdoor"

    strings:
        $domain0 = "2261992.s3.amazonaws.com" nocase
        $domain1 = "acapros-app.s3-us-west-2.amazonaws.com" nocase
        $domain2 = "access.trhammer.com" nocase
        $domain3 = "ahha-asset.s3.ap-northeast-2.amazonaws.com" nocase
        $domain4 = "anynucleus.com" nocase
        $domain5 = "api.farstream.org" nocase
        $domain6 = "api.solveblemten.com" nocase
        $domain7 = "awsdns531.com" nocase
        $domain8 = "bbr-promo.s3.amazonaws.com" nocase
        $domain9 = "be-at-home.s3.ap-northeast-2.amazonaws.com" nocase
        $domain10 = "beansdeals-static.s3.amazonaws.com" nocase
        $domain11 = "bigtimeassets.s3.amazonaws.com" nocase
        $domain12 = "billing.clothworls.com" nocase
        $domain13 = "blog-app-system2.s3.amazonaws.com" nocase
        $domain14 = "breaknlinks.s3.amazonaws.com" nocase
        $domain15 = "c11r.awsdns531.com" nocase
        $domain16 = "cas04.awsdns531.com" nocase
        $domain17 = "cdn-6dd0035.oxcdntech.com" nocase
        $domain18 = "cdn-7a3d.vultr-dns.com" nocase
        $domain19 = "cdn181.awsdns531.com" nocase
        $domain20 = "cdn728a66b0.smartlinkcorp.net" nocase
        $domain21 = "check.sysupdates.org" nocase
        $domain22 = "cloudlibraries.global.ssl.fastly.net" nocase
        $domain23 = "credits.officesanalytics.com" nocase
        $domain24 = "dns2021.net" nocase
        $domain25 = "east.smartpisang.com" nocase
        $domain26 = "esh.hoovernamosong.com" nocase
        $domain27 = "farstream.org" nocase
        $domain28 = "globalnetzone.bcdn.net" nocase
        $domain29 = "helpdesk.stnekpro.com" nocase
        $domain30 = "imap.dateupdata.com" nocase
        $domain31 = "infraredsen.com" nocase
        $domain32 = "jasmine.lhousewares.com" nocase
        $domain33 = "jptomorrow.com" nocase
        $domain34 = "jttoday.net" nocase
        $domain35 = "keyplancorp.com" nocase
        $domain36 = "kia-almotores.s3.amazonaws.com" nocase
        $domain37 = "linkaircdn.com" nocase
        $domain38 = "llnw-dd.awsdns531.com" nocase
        $domain39 = "lyncidc.com" nocase
        $domain40 = "materialplies.com" nocase
        $domain41 = "microware-help.com" nocase
        $domain42 = "mncdntech.com" nocase
        $domain43 = "ms101.cloudshappen.com" nocase
        $domain44 = "music.farstream.org" nocase
        $domain45 = "news.colourtinctem.com" nocase
        $domain46 = "ntp.sysupdates.org" nocase
        $domain47 = "nx2.microware-help.com" nocase
        $domain48 = "officesanalytics.com" nocase
        $domain49 = "omnileadzdev.s3.amazonaws.com" nocase
        $domain50 = "oxcdntech.com" nocase
        $domain51 = "private.royalnas.com" nocase
        $domain52 = "publicdnsau.com" nocase
        $domain53 = "pulseathermakf.com" nocase
        $domain54 = "resource.officesanalytics.com" nocase
        $domain55 = "rthtrade.com" nocase
        $domain56 = "rtsafetech.com" nocase
        $domain57 = "rtsoftcorp.com" nocase
        $domain58 = "rtwebmaster.com" nocase
        $domain59 = "sentinelonepro.com" nocase
        $domain60 = "services.officesanalytics.com" nocase
        $domain61 = "shinas.global.ssl.fastly.net" nocase
        $domain62 = "soffice.officesanalytics.com" nocase
        $domain63 = "substantialeconomy.com" nocase
        $domain64 = "sysupdates.org" nocase
        $domain65 = "telcom.grishamarkovgf8936.workers.dev" nocase
        $domain66 = "trhammer.com" nocase
        $domain67 = "update.sysupdates.org" nocase
        $domain68 = "video.farstream.org" nocase
        $domain69 = "virusblocker.it.com" nocase
        $domain70 = "vpn114240349.softether.net" nocase
        $domain71 = "vpn305783366.softether.net" nocase
        $domain72 = "vpn487875652.softether.net" nocase
        $domain73 = "vpn943823465.softether.net" nocase
        $domain74 = "vultr-dns.com" nocase
        $domain75 = "web9a78bc52.trhammer.com" nocase
        $domain76 = "z7-tech.com" nocase
        $domain77 = "zmailssl3.global.ssl.fastly.net" nocase
        $ip78 = "103.159.133.205"

    condition:
        any of them
}

rule APT_EARTHHUNDUN {
    meta:
        description = "Indicators associated with APT EARTHHUNDUN"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "cloudflaread.quadrantbd.com" nocase
        $domain1 = "cloudsrm.gelatosg.com" nocase
        $domain2 = "freeprous.bakhell.com" nocase
        $domain3 = "rscvmogt.taishanlaw.com" nocase
        $domain4 = "showgyella.quadrantbd.com" nocase
        $domain5 = "smartclouds.gelatosg.com" nocase
        $domain6 = "suitsvm003.rchitecture.org" nocase

    condition:
        any of them
}

rule APT_EARTHKRAHANG {
    meta:
        description = "Indicators associated with APT EARTHKRAHANG"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "dinodas, dinodasrat, linodas"

    strings:
        $domain0 = "115-126-98-204.hkt.cc" nocase
        $domain1 = "118-99-6-202.hkt.cc" nocase
        $domain2 = "centos-yum.com" nocase
        $domain3 = "microsoft-setting.com" nocase
        $domain4 = "microsoft-settings.com" nocase
        $domain5 = "security-microsoft.net" nocase
        $domain6 = "server-microsoft.com" nocase
        $domain7 = "update.centos-yum.com" nocase
        $domain8 = "update.microsoft-setting.com" nocase
        $domain9 = "update.microsoft-settings.com" nocase
        $domain10 = "update.windows.server-microsoft.com" nocase
        $domain11 = "windows.server-microsoft.com" nocase
        $ip12 = "115.126.98.204"
        $ip13 = "118.107.221.43"
        $ip14 = "118.107.221.43"
        $ip15 = "118.107.221.43"
        $ip16 = "118.99.6.202"
        $ip17 = "199.231.211.19"
        $ip18 = "199.231.211.19"

    condition:
        any of them
}

rule APT_EARTHKURMA {
    meta:
        description = "Indicators associated with APT EARTHKURMA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "dmloader, dunloader, frpc"

    strings:
        $domain0 = "dfsg3gfsga.space" nocase
        $domain1 = "igtsadlb2ra.pw" nocase
        $domain2 = "ihyvcs5t.pw" nocase
        $domain3 = "vidsec.cc" nocase
        $ip4 = "103.238.214.88"
        $ip5 = "149.28.147.63"
        $ip6 = "166.88.194.53"
        $ip7 = "185.239.225.106"
        $ip8 = "38.147.191.103"
        $ip9 = "38.60.199.225"
        $ip10 = "45.77.250.21"

    condition:
        any of them
}

rule APT_EARTHWENDIGO {
    meta:
        description = "Indicators associated with APT EARTHWENDIGO"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "anybodyopenfind.com" nocase
        $domain1 = "googletwtw.com" nocase
        $domain2 = "mail2000tw.com" nocase
        $domain3 = "travelsiteadvisor.com" nocase

    condition:
        any of them
}

rule APT_EGOMANIAC {
    meta:
        description = "Indicators associated with APT EGOMANIAC"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "adobupdate.serveftp.com" nocase
        $domain1 = "adobupdate.servehttp.com" nocase
        $domain2 = "antivirus.myftp.org" nocase
        $domain3 = "blogg.serveblog.net" nocase
        $domain4 = "driver.myftp.org" nocase
        $domain5 = "halkinsesitv.com" nocase
        $domain6 = "messenger.serveirc.com" nocase
        $domain7 = "tigereyes2.servepics.com" nocase
        $domain8 = "twiter.serveblog.net" nocase

    condition:
        any of them
}

rule APT_ENERGETICBEAR {
    meta:
        description = "Indicators associated with APT ENERGETICBEAR"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "iron liberty, tg-4192, dragonfly"

    strings:
        $domain0 = "ecco0.b13x.org" nocase
        $domain1 = "kanri.rbridal.net" nocase
        $domain2 = "lite.ultralitedesigns.com" nocase
        $domain3 = "satanal.info" nocase
        $domain4 = "tureg.info" nocase

    condition:
        any of them
}

rule APT_EQUATIONGROUP {
    meta:
        description = "Indicators associated with APT EQUATIONGROUP"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "247adbiz.net" nocase
        $domain1 = "ad-noise.net" nocase
        $domain2 = "ad-servicestats.net" nocase
        $domain3 = "ad-void.com" nocase
        $domain4 = "adsbizsimple.com" nocase
        $domain5 = "adservicestats.com" nocase
        $domain6 = "advancing-technology.com" nocase
        $domain7 = "afkarehroshan.com" nocase
        $domain8 = "amazinggreentechshop.com" nocase
        $domain9 = "arabtechmessenger.net" nocase
        $domain10 = "arm2pie.com" nocase
        $domain11 = "avidnewssource.com" nocase
        $domain12 = "aynachatsrv.com" nocase
        $domain13 = "bazandegan.com" nocase
        $domain14 = "brittlefilet.com" nocase
        $domain15 = "business-made-fun.com" nocase
        $domain16 = "businessdealsblog.com" nocase
        $domain17 = "businessdirectnessource.com" nocase
        $domain18 = "businessedgeadvance.com" nocase
        $domain19 = "charging-technology.com" nocase
        $domain20 = "charmedno1.com" nocase
        $domain21 = "cigape.net" nocase
        $domain22 = "coffeehausblog.com" nocase
        $domain23 = "computertechanalysis.com" nocase
        $domain24 = "config.getmyip.com" nocase
        $domain25 = "cribdare2no.com" nocase
        $domain26 = "crisptic01.net" nocase
        $domain27 = "customerscreensavers.com" nocase
        $domain28 = "damavandkuh.com" nocase
        $domain29 = "darakht.com" nocase
        $domain30 = "dowelsobject.com" nocase
        $domain31 = "downloadmpplayer.com" nocase
        $domain32 = "dt1blog.com" nocase
        $domain33 = "easyadvertonline.com" nocase
        $domain34 = "fliteilex.com" nocase
        $domain35 = "fnlpic.com" nocase
        $domain36 = "following-technology.com" nocase
        $domain37 = "forboringbusinesses.com" nocase
        $domain38 = "forgotten-deals.com" nocase
        $domain39 = "foroushi.net" nocase
        $domain40 = "functional-business.com" nocase
        $domain41 = "gar-tech.com" nocase
        $domain42 = "ghalibaft.com" nocase
        $domain43 = "globalnetworkanalys.com" nocase
        $domain44 = "goldadpremium.com" nocase
        $domain45 = "goodbizez.com" nocase
        $domain46 = "havakhosh.com" nocase
        $domain47 = "honarkhabar.com" nocase
        $domain48 = "honarkhaneh.net" nocase
        $domain49 = "housedman.com" nocase
        $domain50 = "industry-deals.com" nocase
        $domain51 = "islamicmarketing.net" nocase
        $domain52 = "itemagic.net" nocase
        $domain53 = "listennewsnetwork.com" nocase
        $domain54 = "mashinkhabar.com" nocase
        $domain55 = "meevehdar.com" nocase
        $domain56 = "melding-technology.com" nocase
        $domain57 = "micraamber.net" nocase
        $domain58 = "mimicrice.com" nocase
        $domain59 = "monster-ads.net" nocase
        $domain60 = "myhousetechnews.com" nocase
        $domain61 = "newip427.changeip.net" nocase
        $domain62 = "newjunk4u.com" nocase
        $domain63 = "newsterminalvelocity.com" nocase
        $domain64 = "nickleplatedads.com" nocase
        $domain65 = "noticiasftpsrv.com" nocase
        $domain66 = "nowruzbakher.com" nocase
        $domain67 = "parskabab.com" nocase
        $domain68 = "phoneysoap.com" nocase
        $domain69 = "platads.com" nocase
        $domain70 = "posed2shade.com" nocase
        $domain71 = "quickupdateserv.com" nocase
        $domain72 = "quik-serv.com" nocase
        $domain73 = "rampagegramar.com" nocase
        $domain74 = "rapidlyserv.com" nocase
        $domain75 = "rehabretie.com" nocase
        $domain76 = "roshanavar.com" nocase
        $domain77 = "rubi4edit.com" nocase
        $domain78 = "rubiccrum.com" nocase
        $domain79 = "rubriccrumb.com" nocase
        $domain80 = "selective-business.com" nocase
        $domain81 = "serv-load.com" nocase
        $domain82 = "sherkatkonandeh.com" nocase
        $domain83 = "sherkhundi.com" nocase
        $domain84 = "slayinglance.com" nocase
        $domain85 = "speedynewsclips.com" nocase
        $domain86 = "standardsandpraiserepurpose.com" nocase
        $domain87 = "subad-server.com" nocase
        $domain88 = "successful-marketing-now.com" nocase
        $domain89 = "suddenplot.com" nocase
        $domain90 = "taking-technology.com" nocase
        $domain91 = "team4heat.net" nocase
        $domain92 = "teatac4bath.com" nocase
        $domain93 = "techasiamusicsvr.com" nocase
        $domain94 = "technicads.com" nocase
        $domain95 = "technicalconsumerreports.com" nocase
        $domain96 = "technicaldigitalreporting.com" nocase
        $domain97 = "technicserv.com" nocase
        $domain98 = "technicupdate.com" nocase
        $domain99 = "technology-revealed.com" nocase

    condition:
        any of them
}

rule APT_EVAPIKS {
    meta:
        description = "Indicators associated with APT EVAPIKS"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "evapiks, finteam"

    strings:
        $domain0 = "1c-ru.net" nocase
        $domain1 = "intersys32.com" nocase

    condition:
        any of them
}

rule APT_EVASIVEPANDA {
    meta:
        description = "Indicators associated with APT EVASIVEPANDA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "Bronze Highland, Daggerfly"

    strings:
        $domain0 = "flash.governmentmm.com" nocase
        $domain1 = "governmentmm.com" nocase
        $domain2 = "update.devicebug.com" nocase
        $ip3 = "103.96.128.44"
        $ip4 = "103.96.128.44"
        $ip5 = "103.96.131.150"
        $ip6 = "103.96.131.150"
        $ip7 = "122.10.89.170"
        $ip8 = "122.10.89.172"
        $ip9 = "223.165.4.175"
        $ip10 = "45.125.64.200"
        $ip11 = "45.125.64.200"
        $ip12 = "45.125.64.200"
        $ip13 = "45.77.140.81"

    condition:
        any of them
}

rule APT_FAMILIARFEELING {
    meta:
        description = "Indicators associated with APT FAMILIARFEELING"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "comemail.email" nocase
        $domain1 = "comemails.email" nocase
        $domain2 = "commail.co" nocase
        $domain3 = "daynew.today" nocase
        $domain4 = "daynews.today" nocase
        $domain5 = "t1bet.net" nocase
        $domain6 = "tibet-office.net" nocase
        $domain7 = "tibetfreedom.xyz" nocase
        $domain8 = "tibetfrum.info" nocase
        $domain9 = "tibethouse.info" nocase
        $domain10 = "tibetnews.info" nocase
        $domain11 = "tibetnews.today" nocase
        $domain12 = "tibetyouthcongress.com" nocase
        $ip13 = "45.77.45.222"

    condition:
        any of them
}

rule APT_FEROCIOUSKITTEN {
    meta:
        description = "Indicators associated with APT FEROCIOUSKITTEN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "MarkiRAT"

    strings:
        $domain0 = "accountes.google.comesignt.website" nocase
        $domain1 = "accounts.google.comisignin.online" nocase
        $domain2 = "aparat.com-view.space" nocase
        $domain3 = "com-accounts.website" nocase
        $domain4 = "com-signin.site" nocase
        $domain5 = "com-view.org" nocase
        $domain6 = "com-view.space" nocase
        $domain7 = "come-signin.quest" nocase
        $domain8 = "comesignt.website" nocase
        $domain9 = "comi-site.website" nocase
        $domain10 = "comisignin.online" nocase
        $domain11 = "comuk.space" nocase
        $domain12 = "google.comisignin.online" nocase
        $domain13 = "khabarfarsi.com-view.org" nocase
        $domain14 = "microcaft.xyz" nocase
        $domain15 = "microsoft.com-view.space" nocase
        $domain16 = "microsoft.come-site.website" nocase
        $domain17 = "microsoft.comi-site.website" nocase
        $domain18 = "microsoft.comuk.space" nocase
        $domain19 = "microsoft.microcaft.xyz" nocase
        $domain20 = "microsoft.unupdate.ml" nocase
        $domain21 = "microsoft.unupload.xyz" nocase
        $domain22 = "microsoft.updatei.com" nocase
        $domain23 = "min.come-site.website" nocase
        $domain24 = "min.comi-site.website" nocase
        $domain25 = "ns1.com-accounts.website" nocase
        $domain26 = "ns1.com-signin.site" nocase
        $domain27 = "ns2.com-accounts.website" nocase
        $domain28 = "ns2.com-signin.site" nocase
        $domain29 = "unupdate.ml" nocase
        $domain30 = "unupload.xyz" nocase
        $domain31 = "updatei.com" nocase

    condition:
        any of them
}

rule APT_FINFISHER {
    meta:
        description = "Indicators associated with APT FINFISHER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "browserupdate.download" nocase
        $domain1 = "ff-demo.blogdns.org" nocase
        $domain2 = "google.wwwhost.biz" nocase
        $domain3 = "info.dynamic-dns.net" nocase
        $domain4 = "news-youm7.com" nocase
        $domain5 = "pal2me.net" nocase
        $domain6 = "pal4u.net" nocase
        $domain7 = "shop8d.net" nocase
        $domain8 = "tiger.gamma-international.de" nocase
        $domain9 = "workingulf.net" nocase
        $domain10 = "wp.piedslibres.com" nocase
        $ip11 = "108.61.190.183"
        $ip12 = "109.235.67.175"
        $ip13 = "184.82.101.234"
        $ip14 = "184.82.101.234"
        $ip15 = "185.141.24.204"
        $ip16 = "185.25.51.104"
        $ip17 = "213.252.247.105"
        $ip18 = "45.86.136.138"
        $ip19 = "45.86.163.138"
        $ip20 = "79.143.87.216"

    condition:
        any of them
}

rule APT_FLAME {
    meta:
        description = "Indicators associated with APT FLAME"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "autosync.info" nocase
        $domain1 = "bannerspot.in" nocase
        $domain2 = "bannerspot.info" nocase
        $domain3 = "bannerzone.in" nocase
        $domain4 = "chchengine.com" nocase
        $domain5 = "chchengine.net" nocase
        $domain6 = "conf-net.com" nocase
        $domain7 = "dailynewsupdater.com" nocase
        $domain8 = "diznet.biz" nocase
        $domain9 = "dnslocation.info" nocase
        $domain10 = "dnsmask.info" nocase
        $domain11 = "dnsportal.info" nocase
        $domain12 = "dnsupdate.info" nocase
        $domain13 = "eventhosting.com" nocase
        $domain14 = "flashp.webhop.net" nocase
        $domain15 = "flashupdates.info" nocase
        $domain16 = "flushdns.info" nocase
        $domain17 = "isyncautomation.in" nocase
        $domain18 = "isyncautoupdater.in" nocase
        $domain19 = "localgateway.info" nocase
        $domain20 = "micromedia.in" nocase
        $domain21 = "mysync.info" nocase
        $domain22 = "newstatisticfeeder.com" nocase
        $domain23 = "newsync.info" nocase
        $domain24 = "nvidiadrivers.info" nocase
        $domain25 = "nvidiasoft.info" nocase
        $domain26 = "nvidiastream.info" nocase
        $domain27 = "pingserver.info" nocase
        $domain28 = "quick-net.info" nocase
        $domain29 = "rendercodec.info" nocase
        $domain30 = "serveflash.info" nocase
        $domain31 = "serverss.info" nocase
        $domain32 = "smart-access.net" nocase
        $domain33 = "syncdomain.info" nocase
        $domain34 = "synclock.info" nocase
        $domain35 = "syncprovider.info" nocase
        $domain36 = "syncsource.info" nocase
        $domain37 = "syncstream.info" nocase
        $domain38 = "syncupdate.info" nocase
        $domain39 = "traffic-spot.biz" nocase
        $domain40 = "traffic-spot.com" nocase
        $domain41 = "ultrasoft.in" nocase
        $domain42 = "videosync.info" nocase

    condition:
        any of them
}

rule APT_FLAXTYPHOON {
    meta:
        description = "Indicators associated with APT FLAXTYPHOON"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "asljkdqhkhasdq.softether.net" nocase
        $domain1 = "vpn437972693.sednc.cn" nocase
        $domain2 = "vpn472462384.softether.net" nocase

    condition:
        any of them
}

rule APT_FLIGHTNIGHT {
    meta:
        description = "Indicators associated with APT FLIGHTNIGHT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "alfarabischoolgroup.slack.com" nocase
        $domain1 = "solucionesgeofisicas.slack.com" nocase
        $domain2 = "swiftrecruiters.slack.com" nocase
        $domain3 = "telcomprodicci.slack.com" nocase
        $domain4 = "tucker-group.slack.com" nocase

    condition:
        any of them
}

rule APT_FLYINGYETI {
    meta:
        description = "Indicators associated with APT FLYINGYETI"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "cookbox"

    strings:
        $domain0 = "array.myftp.biz" nocase
        $domain1 = "bom02.gotdns.ch" nocase
        $domain2 = "postdock.serveftp.com" nocase
        $domain3 = "worker-polished-union-f396.vqu89698.workers.dev" nocase
        $domain4 = "worker-test-6f41.idv64828.workers.dev" nocase

    condition:
        any of them
}

rule APT_FORUMTROLL {
    meta:
        description = "Indicators associated with APT FORUMTROLL"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "taxoff, team46"

    strings:
        $domain0 = "2025primakovreadings.info" nocase
        $domain1 = "ads-stream-api-v2.global.ssl.fastly.net" nocase
        $domain2 = "advertnow.org" nocase
        $domain3 = "adverty.info" nocase
        $domain4 = "browser-time-stats.global.ssl.fastly.net" nocase
        $domain5 = "bus-pod-tenant.global.ssl.fastly.net" nocase
        $domain6 = "clip-rdp-api.global.ssl.fastly.net" nocase
        $domain7 = "common-rdp-front.global.ssl.fastly.net" nocase
        $domain8 = "corptravel.org" nocase
        $domain9 = "cybers46.team" nocase
        $domain10 = "cybers4646.my.id" nocase
        $domain11 = "e-library.wiki" nocase
        $domain12 = "elibrary.wiki" nocase
        $domain13 = "fast-telemetry-api.global.ssl.fastly.net" nocase
        $domain14 = "feedstream.info" nocase
        $domain15 = "front-static-api.global.ssl.fastly.net" nocase
        $domain16 = "futurebull.live" nocase
        $domain17 = "futurebull.net" nocase
        $domain18 = "globaloneai.com" nocase
        $domain19 = "infosecteam.info" nocase
        $domain20 = "kant300.kantiana.info" nocase
        $domain21 = "kantiana.info" nocase
        $domain22 = "kpmedia.city" nocase
        $domain23 = "main-front-api.global.ssl.fastly.net" nocase
        $domain24 = "mediaoprosso.ru" nocase
        $domain25 = "mil-by.info" nocase
        $domain26 = "moscow.corptravel.org" nocase
        $domain27 = "ms-appdata-fonts.global.ssl.fastly.net" nocase
        $domain28 = "ms-appdata-main.global.ssl.fastly.net" nocase
        $domain29 = "ms-appdata-query.global.ssl.fastly.net" nocase
        $domain30 = "mstn-ru.com" nocase
        $domain31 = "passport.yandeks.info" nocase
        $domain32 = "peerflix.net" nocase
        $domain33 = "perf-service-clients2.global.ssl.fastly.net" nocase
        $domain34 = "planitprima.digital" nocase
        $domain35 = "planitprima.info" nocase
        $domain36 = "planitprima.tech" nocase
        $domain37 = "primakovreadings.info" nocase
        $domain38 = "primakovreadings2025.info" nocase
        $domain39 = "rabotnik.today" nocase
        $domain40 = "rdp-api-front.global.ssl.fastly.net" nocase
        $domain41 = "rdp-query-api.global.ssl.fastly.net" nocase
        $domain42 = "rdp-statistics-api.global.ssl.fastly.net" nocase
        $domain43 = "srv480138.hstgr.cloud" nocase
        $domain44 = "srv484118.hstgr.cloud" nocase
        $domain45 = "status-portal-api.global.ssl.fastly.net" nocase
        $domain46 = "svobody.org" nocase
        $domain47 = "ulitsa.svobody.org" nocase
        $domain48 = "yandeks.info" nocase

    condition:
        any of them
}

rule APT_FRUITYARMOR {
    meta:
        description = "Indicators associated with APT FRUITYARMOR"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "shelves-design.com" nocase
        $domain1 = "weekendstrips.net" nocase

    condition:
        any of them
}

rule APT_GAMAREDON {
    meta:
        description = "Indicators associated with APT GAMAREDON"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-53, actinium, armageddon"

    strings:
        $domain0 = "0.elitoras.ru" nocase
        $domain1 = "0.hustorla.ru" nocase
        $domain2 = "001912184.retarus.ru" nocase
        $domain3 = "02.belkort.ru" nocase
        $domain4 = "02.bortogat.ru" nocase
        $domain5 = "02.domasq.ru" nocase
        $domain6 = "02.elitoras.ru" nocase
        $domain7 = "02.timerto.ru" nocase
        $domain8 = "02.vadilops.ru" nocase
        $domain9 = "02.voranfi.ru" nocase
        $domain10 = "03.bortogat.ru" nocase
        $domain11 = "03.domasq.ru" nocase
        $domain12 = "03.elitoras.ru" nocase
        $domain13 = "03.protimas.ru" nocase
        $domain14 = "03.vadilops.ru" nocase
        $domain15 = "03.voranfi.ru" nocase
        $domain16 = "032xwkhts.corolain.ru" nocase
        $domain17 = "043.libellus.ru" nocase
        $domain18 = "04djgx9h1.corolain.ru" nocase
        $domain19 = "06ez6x.moolin.ru" nocase
        $domain20 = "0apkhude1h8biwnd.spotifik.ru" nocase
        $domain21 = "0e42557e7ebf4251bad6d1e53a680dfb.hopers.ru" nocase
        $domain22 = "0ejbfnz2mkneq14e46.moolin.ru" nocase
        $domain23 = "0enhzs.moolin.ru" nocase
        $domain24 = "0f6vi2h1w.corolain.ru" nocase
        $domain25 = "0gcqbjhae4qj.metanat.ru" nocase
        $domain26 = "0gg2nmb5vnea.jolotras.ru" nocase
        $domain27 = "0hwo4ajnr.corolain.ru" nocase
        $domain28 = "0ievltomh.corolain.ru" nocase
        $domain29 = "0ivrlzyk.moolin.ru" nocase
        $domain30 = "0jbnpsvrh.corolain.ru" nocase
        $domain31 = "0jx4m1e8w7nojrwq2.jolotras.ru" nocase
        $domain32 = "0lhrreh6l2.moolin.ru" nocase
        $domain33 = "0ni4zdjeo.corolain.ru" nocase
        $domain34 = "0nxfri.moolin.ru" nocase
        $domain35 = "0ov.libellus.ru" nocase
        $domain36 = "0rvbbrnjj.corolain.ru" nocase
        $domain37 = "0rweqv9ui.corolain.ru" nocase
        $domain38 = "0sn1nauyr.corolain.ru" nocase
        $domain39 = "0tdkq2ss6yxnebgozvia.jolotras.ru" nocase
        $domain40 = "0u3cn4ywt.corolain.ru" nocase
        $domain41 = "0x2i7nbojeywnm64gfp5.jolotras.ru" nocase
        $domain42 = "0zua3pmf6.corolain.ru" nocase
        $domain43 = "1.hustorla.ru" nocase
        $domain44 = "1.timerto.ru" nocase
        $domain45 = "100.potrakit.ru" nocase
        $domain46 = "100032482.corolain.ru" nocase
        $domain47 = "1000576313.corolain.ru" nocase
        $domain48 = "100066590.corolain.ru" nocase
        $domain49 = "1000940450.retarus.ru" nocase
        $domain50 = "1001434092.retarus.ru" nocase
        $domain51 = "1001438105.corolain.ru" nocase
        $domain52 = "1002180518.corolain.ru" nocase
        $domain53 = "100242942.retarus.ru" nocase
        $domain54 = "1002435167.corolain.ru" nocase
        $domain55 = "1003024331.corolain.ru" nocase
        $domain56 = "1003156034.goloser.ru" nocase
        $domain57 = "1003350707.corolain.ru" nocase
        $domain58 = "1004060582.marak.ru" nocase
        $domain59 = "1004221854.corolain.ru" nocase
        $domain60 = "1004845098.coridas.ru" nocase
        $domain61 = "1005539919.corolain.ru" nocase
        $domain62 = "1005539928.corolain.ru" nocase
        $domain63 = "1006874674.lahatas.ru" nocase
        $domain64 = "100767976.corolain.ru" nocase
        $domain65 = "1007738321.corolain.ru" nocase
        $domain66 = "1007845668.corolain.ru" nocase
        $domain67 = "1008149007.marak.ru" nocase
        $domain68 = "1008334180.coridas.ru" nocase
        $domain69 = "1008855047.corolain.ru" nocase
        $domain70 = "1009060531.corolain.ru" nocase
        $domain71 = "1009596336.corolain.ru" nocase
        $domain72 = "100degrade.mexv.ru" nocase
        $domain73 = "100descendant.erinaceuso.ru" nocase
        $domain74 = "100hit.ru" nocase
        $domain75 = "1010865551.retarus.ru" nocase
        $domain76 = "1011302256.marak.ru" nocase
        $domain77 = "1011607201.goloser.ru" nocase
        $domain78 = "1011888988.corolain.ru" nocase
        $domain79 = "101248036.marak.ru" nocase
        $domain80 = "1012892457.corolain.ru" nocase
        $domain81 = "1012970353.retarus.ru" nocase
        $domain82 = "10129979.chicagosi.ru" nocase
        $domain83 = "1013538088.corolain.ru" nocase
        $domain84 = "1014223537.marak.ru" nocase
        $domain85 = "1014248828.corolain.ru" nocase
        $domain86 = "101445458.retarus.ru" nocase
        $domain87 = "1014576339.corolain.ru" nocase
        $domain88 = "1014620865.corolain.ru" nocase
        $domain89 = "1014765250.corolain.ru" nocase
        $domain90 = "1015038697.coridas.ru" nocase
        $domain91 = "1015151969.goloser.ru" nocase
        $domain92 = "1015453843.corolain.ru" nocase
        $domain93 = "1015749455.marak.ru" nocase
        $domain94 = "1015876339.retarus.ru" nocase
        $domain95 = "1015921716.corolain.ru" nocase
        $domain96 = "1016085247.retarus.ru" nocase
        $domain97 = "1016836962.corolain.ru" nocase
        $domain98 = "1017072518.tutarama.ru" nocase
        $domain99 = "1017225109.chicagosi.ru" nocase
        $ip100 = "124.15.125.1"
        $ip101 = "159.65.63.215"
        $ip102 = "159.65.63.215"
        $ip103 = "162.33.178.129"
        $ip104 = "176.57.220.210"
        $ip105 = "185.45.193.31"
        $ip106 = "188.225.25.132"
        $ip107 = "188.225.44.138"
        $ip108 = "188.225.78.105"
        $ip109 = "194.58.100.230"
        $ip110 = "194.58.56.169"
        $ip111 = "194.58.56.34"
        $ip112 = "194.67.105.190"
        $ip113 = "194.67.109.164"
        $ip114 = "195.62.52.93"
        $ip115 = "195.62.53.63"
        $ip116 = "195.88.208.51"
        $ip117 = "2.59.37.5"
        $ip118 = "31.31.204.59"
        $ip119 = "45.10.246.103"
        $ip120 = "45.61.138.226"
        $ip121 = "5.101.88.18"
        $ip122 = "5.252.176.52"
        $ip123 = "5.252.178.184"
        $ip124 = "84.32.188.31"
        $ip125 = "84.32.188.31"
        $ip126 = "89.223.123.121"
        $ip127 = "92.53.119.52"

    condition:
        any of them
}

rule APT_GAMAREDON_1 {
    meta:
        description = "Indicators associated with APT GAMAREDON-1"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "pterolnk, pterostew, pteroodd"

    strings:
        $domain0 = "0-index.aytashpo.ru" nocase
        $domain1 = "0-tlcovid19-private.veligo.ru" nocase
        $domain2 = "0.agasibi.ru" nocase
        $domain3 = "0.bahramt.ru" nocase
        $domain4 = "0.bayramgo.ru" nocase
        $domain5 = "0.payamt.ru" nocase
        $domain6 = "0031-sysfs.aytashpo.ru" nocase
        $domain7 = "0069-bluetooth-fallback-to-sco-on-error-code-0x10-connect.aytashpo.ru" nocase
        $domain8 = "007b9f33257f40a1ae9ad17e81497620.hopers.ru" nocase
        $domain9 = "01.arasht.ru" nocase
        $domain10 = "01.bahramt.ru" nocase
        $domain11 = "01.payamt.ru" nocase
        $domain12 = "02.nightmit.ru" nocase
        $domain13 = "02.payamt.ru" nocase
        $domain14 = "03.arasht.ru" nocase
        $domain15 = "03.bahramt.ru" nocase
        $domain16 = "03.payamt.ru" nocase
        $domain17 = "03.vilviton.ru" nocase
        $domain18 = "038422dd0aa7bc54f58f64956b4d8724.hitorova.ru" nocase
        $domain19 = "09cb592b8982431fbdeba0d65dcedb47.hopers.ru" nocase
        $domain20 = "0aaqhwf689wwecsz.stradrol.ru" nocase
        $domain21 = "0b88948c8cc34efca2dfad9841aee4a5.vasimgo.ru" nocase
        $domain22 = "0fd3a83fa12b4f21b96c61e0791b2826.validgo.ru" nocase
        $domain23 = "0qh7kk5z-80.euw.devtunnels.ms" nocase
        $domain24 = "0wlxbqv4pfbm.celticso.ru" nocase
        $domain25 = "0wsw44lbs6.paramants.ru" nocase
        $domain26 = "0xgggj25-80.euw.devtunnels.ms" nocase
        $domain27 = "1.arasht.ru" nocase
        $domain28 = "1.bayramgo.ru" nocase
        $domain29 = "1.payamt.ru" nocase
        $domain30 = "10.bahramt.ru" nocase
        $domain31 = "10.bayramgo.ru" nocase
        $domain32 = "10.payamt.ru" nocase
        $domain33 = "1000000109.pasamart.ru" nocase
        $domain34 = "1000061142.ganara.ru" nocase
        $domain35 = "100064636.polutar.ru" nocase
        $domain36 = "1001012353.wicksl.ru" nocase
        $domain37 = "100103493.makasd.ru" nocase
        $domain38 = "1001241254.humahu.ru" nocase
        $domain39 = "100131717.dfgqdsd.ru" nocase
        $domain40 = "1001583341.wicksl.ru" nocase
        $domain41 = "1001774425.makasd.ru" nocase
        $domain42 = "1001812139.gokols.ru" nocase
        $domain43 = "1002139495.ganara.ru" nocase
        $domain44 = "100215046.gokols.ru" nocase
        $domain45 = "1002427615.patrios.ru" nocase
        $domain46 = "1002763297.patrios.ru" nocase
        $domain47 = "1002834610.kurapat.ru" nocase
        $domain48 = "1002928871.makasd.ru" nocase
        $domain49 = "1003576324.kurapat.ru" nocase
        $domain50 = "1003693694.marak.ru" nocase
        $domain51 = "1003878491.faturan.ru" nocase
        $domain52 = "1004070485.humahu.ru" nocase
        $domain53 = "1004073294.kurapat.ru" nocase
        $domain54 = "1004156947.gokols.ru" nocase
        $domain55 = "1004539663.bulot.ru" nocase
        $domain56 = "1004717876.gokols.ru" nocase
        $domain57 = "1005607677.gokols.ru" nocase
        $domain58 = "1005965674.gokols.ru" nocase
        $domain59 = "1005986379.gokols.ru" nocase
        $domain60 = "1006140160.gokols.ru" nocase
        $domain61 = "1006523449.makasd.ru" nocase
        $domain62 = "100743407.marak.ru" nocase
        $domain63 = "1007676970.baruta.ru" nocase
        $domain64 = "1007917588.patrios.ru" nocase
        $domain65 = "1008281127.makasd.ru" nocase
        $domain66 = "1008822253.rieturc.ru" nocase
        $domain67 = "1008954144.rieturc.ru" nocase
        $domain68 = "1009104060axw.havxcq.ru" nocase
        $domain69 = "1009207443.makasd.ru" nocase
        $domain70 = "1009365463.kurapat.ru" nocase
        $domain71 = "1009522443.bulot.ru" nocase
        $domain72 = "1009689332.gokols.ru" nocase
        $domain73 = "100asc.crudoes.ru" nocase
        $domain74 = "100december.intigambi.ru" nocase
        $domain75 = "100decent.alceaso.ru" nocase
        $domain76 = "100decent.barutipi.ru" nocase
        $domain77 = "100decidedly.artavazd.xyz" nocase
        $domain78 = "100decisive.alceaso.ru" nocase
        $domain79 = "100declared.alceaso.ru" nocase
        $domain80 = "100declared.savalanpo.ru" nocase
        $domain81 = "100decline.alceaso.ru" nocase
        $domain82 = "100decline.intigambi.ru" nocase
        $domain83 = "100decline.oddzhiso.ru" nocase
        $domain84 = "100decoy.alceaso.ru" nocase
        $domain85 = "100deed.rasimla.ru" nocase
        $domain86 = "100deeper.intigambi.ru" nocase
        $domain87 = "100deeply.alceaso.ru" nocase
        $domain88 = "100default.alceaso.ru" nocase
        $domain89 = "100defence.rasimla.ru" nocase
        $domain90 = "100defend.vifpor.ru" nocase
        $domain91 = "100defense.alceaso.ru" nocase
        $domain92 = "100defensive.alceaso.ru" nocase
        $domain93 = "100defensive.rasimla.ru" nocase
        $domain94 = "100define.vifpor.ru" nocase
        $domain95 = "100defined.intigambi.ru" nocase
        $domain96 = "100definition.alceaso.ru" nocase
        $domain97 = "100degrade.intigambi.ru" nocase
        $domain98 = "100degrade.rasimla.ru" nocase
        $domain99 = "100degree.daglarho.ru" nocase
        $ip100 = "107.189.25.145"
        $ip101 = "141.8.192.151"
        $ip102 = "141.8.197.42"
        $ip103 = "159.89.205.135"
        $ip104 = "165.22.170.129"
        $ip105 = "206.189.188.38"
        $ip106 = "5.252.178.181"
        $ip107 = "89.124.79.33"
        $ip108 = "89.124.88.211"

    condition:
        any of them
}

rule APT_GAZA {
    meta:
        description = "Indicators associated with APT GAZA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "ta402"

    strings:
        $domain0 = "0arfx4grailorhvlicbj.servehumour.com" nocase
        $domain1 = "0n4tblbdfncaauxioxto.ddns.net" nocase
        $domain2 = "3tshhm1nfphiqqrxbi8c.servehumour.com" nocase
        $domain3 = "aaas.mefound.com" nocase
        $domain4 = "acc.buybit.us" nocase
        $domain5 = "accounts-helper.ml" nocase
        $domain6 = "adfdafsggdfgdfgsagaer.blogsyte.com" nocase
        $domain7 = "adsmartweb9.com" nocase
        $domain8 = "ajaxo.zapto.org" nocase
        $domain9 = "alasra-paper.duckdns.org" nocase
        $domain10 = "aqs.filezellasd.co.vu" nocase
        $domain11 = "aracaravan.com" nocase
        $domain12 = "backjadwer.bounceme.net" nocase
        $domain13 = "backop.mooo.com" nocase
        $domain14 = "bandao.publicvm.com" nocase
        $domain15 = "baz.downloadcor.xyz" nocase
        $domain16 = "beatricewarner.com" nocase
        $domain17 = "bulk-smtp.xyz" nocase
        $domain18 = "bundanesia.com" nocase
        $domain19 = "buy.israel-shipment.xyz" nocase
        $domain20 = "bypasstesting.servehalflife.com" nocase
        $domain21 = "cbbnews.tk" nocase
        $domain22 = "cccam.serveblog.net" nocase
        $domain23 = "checktest.www1.biz" nocase
        $domain24 = "chromeupdt.tk" nocase
        $domain25 = "cl170915.otzo.com" nocase
        $domain26 = "claire-conway.com" nocase
        $domain27 = "cloudserviceapi.online" nocase
        $domain28 = "cnaci8gyolttkgmguzog.ignorelist.com" nocase
        $domain29 = "cyaxsnieccunozn0erih.mefound.com" nocase
        $domain30 = "cyber-peace.org" nocase
        $domain31 = "cyber18.no-ip.net" nocase
        $domain32 = "d.nabzerd.co.vu" nocase
        $domain33 = "dapoerwedding.com" nocase
        $domain34 = "data-server.cloudns.club" nocase
        $domain35 = "deapka.sytes.net" nocase
        $domain36 = "debka.ga" nocase
        $domain37 = "depka.sytes.net" nocase
        $domain38 = "dfwsd.co.vu" nocase
        $domain39 = "direct-marketing.ml" nocase
        $domain40 = "directl.otzo.com" nocase
        $domain41 = "dji-msi.2waky.com" nocase
        $domain42 = "dnsfor.dnsfor.me" nocase
        $domain43 = "dontrplay.tk" nocase
        $domain44 = "dorcertg.otzo.com" nocase
        $domain45 = "down.downloadcor.xyz" nocase
        $domain46 = "down.supportcom.xyz" nocase
        $domain47 = "download.data-server.cloudns.club" nocase
        $domain48 = "download.likescandy.com" nocase
        $domain49 = "downloadlog.linkpc.net" nocase
        $domain50 = "downloadmyhost.zapto.org" nocase
        $domain51 = "downloadskype.cf" nocase
        $domain52 = "drivres-update.info" nocase
        $domain53 = "duntat.zapto.org" nocase
        $domain54 = "easyuploadservice.com" nocase
        $domain55 = "ed3qy5yioryitoturysuiu.otzo.com" nocase
        $domain56 = "email-market.ml" nocase
        $domain57 = "email-test.ml" nocase
        $domain58 = "emailotest.co.vu" nocase
        $domain59 = "emobileservices.club" nocase
        $domain60 = "facetoo.co.vu" nocase
        $domain61 = "fastbingcom.sytes.net" nocase
        $domain62 = "fatihah.zapto.org" nocase
        $domain63 = "filezellla.otzo.com" nocase
        $domain64 = "freshchrysanthemum.com" nocase
        $domain65 = "fulltest.yourtrap.com" nocase
        $domain66 = "gabro.xxuz.com" nocase
        $domain67 = "gamail.goaglesmtp.co.vu" nocase
        $domain68 = "games.buybit.us" nocase
        $domain69 = "gaonsmom.redirectme.net" nocase
        $domain70 = "gfhbgfzfgfgfgdg.otzo.com" nocase
        $domain71 = "goldenlines.site" nocase
        $domain72 = "goodday.zapto.org" nocase
        $domain73 = "goodwebmail.tk" nocase
        $domain74 = "google.com.r3irv2ykn0qnd7vr7sqv7kg2qho3ab5tngl5avxi5iimz1jxw9pa9.uae.kim" nocase
        $domain75 = "googlecombq6xx.ddns.net" nocase
        $domain76 = "googledomain.otzo.com" nocase
        $domain77 = "gov.uae.kim" nocase
        $domain78 = "gq4bp1baxfiblzqk.mrbasic.com" nocase
        $domain79 = "h908926f.beget.tech" nocase
        $domain80 = "haartezenglish.redirectme.net" nocase
        $domain81 = "haartezenglish.strangled.net" nocase
        $domain82 = "hamas-wathaq.duckdns.org" nocase
        $domain83 = "hdgshfdgh.co.vu" nocase
        $domain84 = "healthcaption.com" nocase
        $domain85 = "help2014.linkpc.net" nocase
        $domain86 = "helthnews.ga" nocase
        $domain87 = "hnoor.newphoneapp.com" nocase
        $domain88 = "hostgatr.mrface.com" nocase
        $domain89 = "hr.goaglesmtp.co.vu" nocase
        $domain90 = "httpo.sytes.net" nocase
        $domain91 = "idf.idfcom.co.vu" nocase
        $domain92 = "imazing.ga" nocase
        $domain93 = "inclusive-economy.com" nocase
        $domain94 = "info.intarspace.co.vu" nocase
        $domain95 = "infoblusa.tk" nocase
        $domain96 = "internetdownloadr.publicvm.com" nocase
        $domain97 = "iphonenewsd.co.vu" nocase
        $domain98 = "itresolver.online" nocase
        $domain99 = "jake.support-sales.tk" nocase
        $ip100 = "149.28.137.224"
        $ip101 = "79.124.60.40"

    condition:
        any of them
}

rule APT_GHOSTEMPEROR {
    meta:
        description = "Indicators associated with APT GHOSTEMPEROR"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "entryshell, sparrowdoor, xiangoop"

    strings:
        $domain0 = "aftercould.com" nocase
        $domain1 = "amelicen.com" nocase
        $domain2 = "datacentreonline.com" nocase
        $domain3 = "dateupdata.com" nocase
        $domain4 = "freedecrease.com" nocase
        $domain5 = "game.newfreepre.com" nocase
        $domain6 = "imap.dateupdata.com" nocase
        $domain7 = "imap.newlylab.com" nocase
        $domain8 = "imap.webdignusdata.com" nocase
        $domain9 = "mail.reclubpress.com" nocase
        $domain10 = "newfreepre.com" nocase
        $domain11 = "newlylab.com" nocase
        $domain12 = "reclubpress.com" nocase
        $domain13 = "webdignusdata.com" nocase
        $ip14 = "103.85.25.166"
        $ip15 = "107.148.165.158"
        $ip16 = "107.148.165.158"
        $ip17 = "154.223.135.214"
        $ip18 = "154.223.135.214"
        $ip19 = "27.102.113.240"
        $ip20 = "27.102.113.240"
        $ip21 = "27.102.113.57"
        $ip22 = "27.102.113.57"
        $ip23 = "27.102.114.55"
        $ip24 = "27.102.114.55"
        $ip25 = "27.102.115.51"
        $ip26 = "27.102.115.51"
        $ip27 = "27.102.129.120"
        $ip28 = "27.102.129.120"

    condition:
        any of them
}

rule APT_GLASSES {
    meta:
        description = "Indicators associated with APT GLASSES"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "ewplus.com" nocase
        $domain1 = "tcw.homier.com" nocase

    condition:
        any of them
}

rule APT_GOLDDRAGON {
    meta:
        description = "Indicators associated with APT GOLDDRAGON"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "brave prince, gold dragon, ghost419"

    strings:
        $domain0 = "0523qyfw.cn" nocase
        $domain1 = "0523qyfw.com" nocase
        $domain2 = "eodo1.000webhostapp.com" nocase
        $domain3 = "followgho.byethost7.com" nocase
        $domain4 = "ink.inkboom.co.kr" nocase
        $domain5 = "nid-help-pchange.atwebpages.com" nocase
        $domain6 = "nyazz.com" nocase
        $domain7 = "one.0523qyfw.com" nocase
        $domain8 = "redi.nyazz.com" nocase
        $domain9 = "scrt1.nyazz.com" nocase
        $domain10 = "ssh.0523qyfw.cn" nocase
        $domain11 = "ssh.0523qyfw.com" nocase
        $domain12 = "trydai.000webhostapp.com" nocase
        $ip13 = "107.148.61.127"
        $ip14 = "154.19.200.133"

    condition:
        any of them
}

rule APT_GOLDENJACKAL {
    meta:
        description = "Indicators associated with APT GOLDENJACKAL"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "83.24.9.124"

    condition:
        any of them
}

rule APT_GOLDENRAT {
    meta:
        description = "Indicators associated with APT GOLDENRAT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bashalalassad1sea.noip.me" nocase
        $domain1 = "bbbb4.noip.me" nocase
        $domain2 = "chatsecurelite.uk.to" nocase
        $domain3 = "chatsecurelite.us.to" nocase
        $domain4 = "telegram.strangled.net" nocase
        $domain5 = "telgram.strangled.net" nocase

    condition:
        any of them
}

rule APT_GOLDMELODY {
    meta:
        description = "Indicators associated with APT GOLDMELODY"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "AUDITUNNEL, IHS Back-Connect backdoor"

    strings:
        $ip0 = "149.28.193.216"
        $ip1 = "149.28.200.140"
        $ip2 = "149.28.207.120"
        $ip3 = "195.123.240.183"
        $ip4 = "40.76.20.11"
        $ip5 = "64.190.113.185"
        $ip6 = "67.205.135.147"

    condition:
        any of them
}

rule APT_GOLDMOUSE {
    meta:
        description = "Indicators associated with APT GOLDMOUSE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-27, goldmouse"

    strings:
        $ip0 = "82.137.255.56"
        $ip1 = "82.137.255.56"
        $ip2 = "82.137.255.56"
        $ip3 = "82.137.255.56"
        $ip4 = "82.137.255.56"

    condition:
        any of them
}

rule APT_GOPHERWHISPER {
    meta:
        description = "Indicators associated with APT GOPHERWHISPER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "compactgopher, laxgopher, ratgopher"

    strings:
        $ip0 = "43.231.113.50"
        $ip1 = "43.231.113.50"

    condition:
        any of them
}

rule APT_GORGON {
    meta:
        description = "Indicators associated with APT GORGON"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "0-day.us" nocase
        $domain1 = "1688jtn.com" nocase
        $domain2 = "41230077.net" nocase
        $domain3 = "6474sss.com" nocase
        $domain4 = "acorn-paper.com" nocase
        $domain5 = "asaigoldenrice.com" nocase
        $domain6 = "asdiamecwecw8cew.blogspot.com" nocase
        $domain7 = "bjm9.blogspot.com" nocase
        $domain8 = "brevini-france.cf" nocase
        $domain9 = "buydildoonline.blogspot.com" nocase
        $domain10 = "bylgay.hopto.org" nocase
        $domain11 = "diamondfoxpanel.ml" nocase
        $domain12 = "dixis.bounceme.net" nocase
        $domain13 = "downloads.blogsyte.com" nocase
        $domain14 = "emawattttson.blogspot.com" nocase
        $domain15 = "fast-cargo.com" nocase
        $domain16 = "gritodopovo.com.br" nocase
        $domain17 = "grupomsi.com" nocase
        $domain18 = "guelphupholstery.com" nocase
        $domain19 = "hongmenwenhua.com" nocase
        $domain20 = "ichoubyou.net" nocase
        $domain21 = "klapki.online" nocase
        $domain22 = "microsoftoutlook.duckdns.org" nocase
        $domain23 = "miganshumarataa.blogspot.com" nocase
        $domain24 = "ocha-gidi.xyz" nocase
        $domain25 = "onedrivenet.xyz" nocase
        $domain26 = "panelonetwothree.ga" nocase
        $domain27 = "panelonetwothree.ml" nocase
        $domain28 = "qp0o1j3-dmv4kwncw8e.win" nocase
        $domain29 = "securebotnetpanel.tk" nocase
        $domain30 = "stemtopx.com" nocase
        $domain31 = "stevemike-fireforce.info" nocase
        $domain32 = "stevemikeforce.com" nocase
        $domain33 = "sukfat.com" nocase
        $domain34 = "sxasxasxssaxxsasxasx.blogspot.com" nocase
        $domain35 = "theaterloops.com" nocase
        $domain36 = "thedip.zone" nocase
        $domain37 = "tourismmanagement.mba" nocase
        $domain38 = "treffictesgn.blogspot.com" nocase
        $domain39 = "x-ghost91.ddns.net" nocase
        $domain40 = "xaasxasxasx.blogspot.com" nocase
        $domain41 = "xyz-storez.xyz" nocase
        $domain42 = "ycsfuoabdicating.review" nocase
        $domain43 = "zupaservices.info" nocase
        $ip44 = "196.185.215.228"

    condition:
        any of them
}

rule APT_GOTHICPANDA {
    meta:
        description = "Indicators associated with APT GOTHICPANDA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt3, apt-c-3, ups"

    strings:
        $domain0 = "bedircati.com" nocase
        $domain1 = "lamb-site.com" nocase
        $domain2 = "link.angellroofing.com" nocase
        $domain3 = "playboysplus.com" nocase
        $domain4 = "psa.perrydale.com" nocase
        $domain5 = "report.perrydale.com" nocase
        $domain6 = "rpt.perrydale.com" nocase
        $domain7 = "securitywap.com" nocase
        $domain8 = "vic.perrydale.com" nocase
        $domain9 = "walterclean.com" nocase

    condition:
        any of them
}

rule APT_GRAYLING {
    meta:
        description = "Indicators associated with APT GRAYLING"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "45.148.120.23"

    condition:
        any of them
}

rule APT_GREENSPOT {
    meta:
        description = "Indicators associated with APT GREENSPOT"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-01, poison ivy"

    strings:
        $domain0 = "126mailserver.serveftp.com" nocase
        $domain1 = "143-244-183-240.cprapid.com" nocase
        $domain2 = "360urlscan.com" nocase
        $domain3 = "64-176-165-42.cprapid.com" nocase
        $domain4 = "6c99b2c4cf5a.expolebanon.com" nocase
        $domain5 = "access.webplurk.com" nocase
        $domain6 = "accounts126.com" nocase
        $domain7 = "afte856422126.com" nocase
        $domain8 = "aliago.dyndns.dk" nocase
        $domain9 = "annie165.zyns.com" nocase
        $domain10 = "app.newfacebk.com" nocase
        $domain11 = "as1688.webhop.org" nocase
        $domain12 = "atrew56877.com" nocase
        $domain13 = "avdsart.com" nocase
        $domain14 = "babana.wikaba.com" nocase
        $domain15 = "backaaa.beijingdasihei.com" nocase
        $domain16 = "bearingonly.rebatesrule.net" nocase
        $domain17 = "bribieislandhistory.com" nocase
        $domain18 = "bt0116.servebbs.net" nocase
        $domain19 = "buendnis-fuer-kinder.com" nocase
        $domain20 = "caac-cn.com" nocase
        $domain21 = "caac-cn.org" nocase
        $domain22 = "canberk.gecekodu.com" nocase
        $domain23 = "ceepitbj.servepics.com" nocase
        $domain24 = "censor.site" nocase
        $domain25 = "center-gai.com" nocase
        $domain26 = "certifications.services" nocase
        $domain27 = "chamber.icu" nocase
        $domain28 = "check.blogdns.com" nocase
        $domain29 = "china.serveblog.net" nocase
        $domain30 = "chinamil.lflink.com" nocase
        $domain31 = "chinmori.com" nocase
        $domain32 = "cloudattaches-126.com" nocase
        $domain33 = "clouddevice.site" nocase
        $domain34 = "clouddrive.space" nocase
        $domain35 = "cluster.safe360.dns05.com" nocase
        $domain36 = "cnsa163.com" nocase
        $domain37 = "cnwww.m-music.net" nocase
        $domain38 = "co-journal163.com" nocase
        $domain39 = "co-journalyeah.net" nocase
        $domain40 = "comehigh.mefound.com" nocase
        $domain41 = "contracter.org" nocase
        $domain42 = "daotongintelligence163.com" nocase
        $domain43 = "datamasterw.com" nocase
        $domain44 = "difusora890.com" nocase
        $domain45 = "dockerswarm2.cic-webpro.com" nocase
        $domain46 = "download163ease.com" nocase
        $domain47 = "eadfg56877.com" nocase
        $domain48 = "eco163.com" nocase
        $domain49 = "eleusina.com" nocase
        $domain50 = "emailser163.serveusers.com" nocase
        $domain51 = "esrebrenica.com" nocase
        $domain52 = "fevupdate.ocry.com" nocase
        $domain53 = "fff.dynamic-dns.net" nocase
        $domain54 = "fored126.com" nocase
        $domain55 = "gaewaa.upgrinfo.com" nocase
        $domain56 = "geiwoaaa.qpoe.com" nocase
        $domain57 = "givemea.ygto.com" nocase
        $domain58 = "givemeaaa.upgrinfo.com" nocase
        $domain59 = "gjfgw163.com" nocase
        $domain60 = "goldlion.mefound.com" nocase
        $domain61 = "gottardo-fs.com" nocase
        $domain62 = "gscmovies.com" nocase
        $domain63 = "gugupd.008.net" nocase
        $domain64 = "guliu2008.9966.org" nocase
        $domain65 = "gxbxzszl163.com" nocase
        $domain66 = "gzkfj20240923.com" nocase
        $domain67 = "h2024163.com" nocase
        $domain68 = "hcqtji.com" nocase
        $domain69 = "hopemilltheatre.com" nocase
        $domain70 = "hostmaster.thicongcayxanh.com.vn" nocase
        $domain71 = "howtochoosealawschool.com" nocase
        $domain72 = "hunter.luminousstore.cloud" nocase
        $domain73 = "huntercomunity.pterodactyl.web.id" nocase
        $domain74 = "hy-zhqopin.mynumber.org" nocase
        $domain75 = "hyssjc.securitytactics.com" nocase
        $domain76 = "im1.dewabiz.com" nocase
        $domain77 = "influxdb.kanoak.com" nocase
        $domain78 = "intent.cyou" nocase
        $domain79 = "janheweliusz.com" nocase
        $domain80 = "jason.zyns.com" nocase
        $domain81 = "javainfo.upgrinfo.com" nocase
        $domain82 = "jerry.jkub.com" nocase
        $domain83 = "k2024163.com" nocase
        $domain84 = "kav2011.mooo.com" nocase
        $domain85 = "kouwel.zapto.org" nocase
        $domain86 = "krogoo.net" nocase
        $domain87 = "l12254686126.com" nocase
        $domain88 = "l12457784126.com" nocase
        $domain89 = "l2024163.com" nocase
        $domain90 = "l58785163.com" nocase
        $domain91 = "l588188126.com" nocase
        $domain92 = "l5886797126.com" nocase
        $domain93 = "l63service.serveuser.com" nocase
        $domain94 = "l8630639126.com" nocase
        $domain95 = "laizaow.mefound.com" nocase
        $domain96 = "ll63.net" nocase
        $domain97 = "localhosts.ddns.us" nocase
        $domain98 = "locarmi.com" nocase
        $domain99 = "lorenlegarda.com" nocase
        $ip100 = "128.199.134.3"
        $ip101 = "158.247.208.174"
        $ip102 = "202.182.108.174"
        $ip103 = "207.148.126.90"

    condition:
        any of them
}

rule APT_GREF {
    meta:
        description = "Indicators associated with APT GREF"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "6006.secpert.com" nocase
        $domain1 = "6006.upupdate.cn" nocase
        $domain2 = "789aa654.top" nocase
        $domain3 = "adoptewer.com" nocase
        $domain4 = "allshell.net" nocase
        $domain5 = "allwhatsapp.net" nocase
        $domain6 = "amote-366.vicp.cc" nocase
        $domain7 = "anar.gleeze.com" nocase
        $domain8 = "android.apps.us.to" nocase
        $domain9 = "androidapps.duia.in" nocase
        $domain10 = "androidapps.fvk.cc" nocase
        $domain11 = "androidapps.home.hn.org" nocase
        $domain12 = "androidapps.jetos.com" nocase
        $domain13 = "androidapps.linkpc.net" nocase
        $domain14 = "androidapps.myfirewall.org" nocase
        $domain15 = "androidapps.nerdpol.ovh" nocase
        $domain16 = "androidapps.npff.co" nocase
        $domain17 = "androidapps.nsupdate.info" nocase
        $domain18 = "androidapps.spdns.eu" nocase
        $domain19 = "androidapps.spdns.org" nocase
        $domain20 = "androidapps.tempors.com" nocase
        $domain21 = "androidsapps.ml" nocase
        $domain22 = "api--telegram.ru" nocase
        $domain23 = "api.telegram5.org" nocase
        $domain24 = "api.telegramrc.com" nocase
        $domain25 = "app.telegramrc.com" nocase
        $domain26 = "attoo1s.com" nocase
        $domain27 = "babyedu-online.com" nocase
        $domain28 = "battle.com.tw" nocase
        $domain29 = "bhvghg.com" nocase
        $domain30 = "cdngoogle.com" nocase
        $domain31 = "cisco-inc.net" nocase
        $domain32 = "coco.wikaba.com" nocase
        $domain33 = "comeflxyr.com" nocase
        $domain34 = "cookedu-online.com" nocase
        $domain35 = "diablo-iii.mobi" nocase
        $domain36 = "down.telegramxo.com" nocase
        $domain37 = "englishedu-online.com" nocase
        $domain38 = "everydayinfo.top" nocase
        $domain39 = "fgttgvh.com" nocase
        $domain40 = "flygram.org" nocase
        $domain41 = "flygram.orgproxy1.signalplus.org" nocase
        $domain42 = "fufijxgkg.com" nocase
        $domain43 = "gefacebook.com" nocase
        $domain44 = "ggl.whoscaller.net" nocase
        $domain45 = "gheyret.com" nocase
        $domain46 = "gheyret.net" nocase
        $domain47 = "goldplusapp.net" nocase
        $domain48 = "googleanalyseservice.net" nocase
        $domain49 = "googlemapsoftware.com" nocase
        $domain50 = "googlleservice.com" nocase
        $domain51 = "graphicdata.net" nocase
        $domain52 = "heartsys.dnsapi.info" nocase
        $domain53 = "ignitetibet.net" nocase
        $domain54 = "in7n.com" nocase
        $domain55 = "jindjjdtc.com" nocase
        $domain56 = "jkapp88.top" nocase
        $domain57 = "joke.upupdate.cn" nocase
        $domain58 = "k1-ai-jk.789aa654.top" nocase
        $domain59 = "k3-ai-jk.jkapp88.top" nocase
        $domain60 = "kasparsky.net" nocase
        $domain61 = "kmcuft.com" nocase
        $domain62 = "kocrmicrosoft.com" nocase
        $domain63 = "microsoft.org.tw" nocase
        $domain64 = "microsoftdomainadmin.com" nocase
        $domain65 = "microsoftsp3.com" nocase
        $domain66 = "microsoftupdate.ws" nocase
        $domain67 = "mremote.biz" nocase
        $domain68 = "msftncsl.com" nocase
        $domain69 = "msnupdate.bz" nocase
        $domain70 = "nortonservice.net" nocase
        $domain71 = "o21q.com" nocase
        $domain72 = "officescan.biz" nocase
        $domain73 = "omarwhatsapp.org" nocase
        $domain74 = "oprea.biz" nocase
        $domain75 = "orgproxy1.signalplus.org" nocase
        $domain76 = "phpyahoo.mrbasic.com" nocase
        $domain77 = "powershell.com.tw" nocase
        $domain78 = "s101.secpert.com" nocase
        $domain79 = "s2.upupdate.cn" nocase
        $domain80 = "signalplus.org" nocase
        $domain81 = "softwareupdatevmware.com" nocase
        $domain82 = "square-enix.us" nocase
        $domain83 = "ss903.w3.ezua.com" nocase
        $domain84 = "ss904.w3.ezua.com" nocase
        $domain85 = "symantecupdate.net" nocase
        $domain86 = "sz.secpert.com" nocase
        $domain87 = "telegram5.org" nocase
        $domain88 = "telegramrc.com" nocase
        $domain89 = "telegramxo.com" nocase
        $domain90 = "tengri.ooguy.com" nocase
        $domain91 = "tgpc.telegramrc.com" nocase
        $domain92 = "thetubeplus.com" nocase
        $domain93 = "tibetone.org" nocase
        $domain94 = "tinmf.org" nocase
        $domain95 = "tree.ddns.us" nocase
        $domain96 = "tryhrwserf.com" nocase
        $domain97 = "tubevideoplus.org" nocase
        $domain98 = "turknews-online.com" nocase
        $domain99 = "turkyedu-online.com" nocase
        $ip100 = "103.27.186.156"
        $ip101 = "103.27.186.195"
        $ip102 = "142.132.131.28"
        $ip103 = "142.132.131.28"
        $ip104 = "142.132.131.28"
        $ip105 = "142.132.131.28"
        $ip106 = "148.251.87.245"
        $ip107 = "148.251.87.247"
        $ip108 = "148.251.87.247"
        $ip109 = "148.251.87.247"
        $ip110 = "148.251.87.247"
        $ip111 = "154.202.59.169"
        $ip112 = "154.212.147.129"
        $ip113 = "185.239.227.14"
        $ip114 = "195.154.60.3"
        $ip115 = "195.154.60.3"
        $ip116 = "195.154.60.3"
        $ip117 = "195.154.60.3"
        $ip118 = "217.163.29.84"
        $ip119 = "23.88.28.222"
        $ip120 = "45.133.238.92"
        $ip121 = "45.154.12.132"
        $ip122 = "45.154.12.151"
        $ip123 = "45.154.12.202"
        $ip124 = "45.63.89.238"
        $ip125 = "62.210.28.116"
        $ip126 = "62.210.30.158"
        $ip127 = "62.210.30.158"
        $ip128 = "62.210.30.158"
        $ip129 = "62.210.30.158"
        $ip130 = "92.118.189.164"
        $ip131 = "95.216.187.21"

    condition:
        any of them
}

rule APT_GREYENERGY {
    meta:
        description = "Indicators associated with APT GREYENERGY"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "82.118.236.23"
        $ip1 = "82.118.236.23"
        $ip2 = "88.198.13.116"
        $ip3 = "88.198.13.116"

    condition:
        any of them
}

rule APT_GROUNDBAIT {
    meta:
        description = "Indicators associated with APT GROUNDBAIT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bolepaund.com" nocase
        $domain1 = "disk-fulldatabase.rhcloud.com" nocase
        $domain2 = "gils.ho.ua" nocase
        $domain3 = "lefting.org" nocase
        $domain4 = "literat.ho.ua" nocase
        $domain5 = "wallejob.in.ua" nocase
        $domain6 = "wallex.ho.ua" nocase

    condition:
        any of them
}

rule APT_GROUP5 {
    meta:
        description = "Indicators associated with APT GROUP5"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "assadcrimes.info" nocase
        $domain1 = "crypter.ir" nocase
        $domain2 = "crypting.org" nocase
        $domain3 = "server22.rayanegarco.com" nocase

    condition:
        any of them
}

rule APT_HACKINGTEAM {
    meta:
        description = "Indicators associated with APT HACKINGTEAM"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "androidgplay.us.to" nocase
        $domain1 = "ar-24.com" nocase
        $domain2 = "bijiaexhibition.com" nocase
        $domain3 = "boardingpasstohome.com" nocase
        $domain4 = "cdc-asia.org" nocase
        $domain5 = "droidlatestnews.com" nocase
        $domain6 = "enjoyyourandroid.com" nocase
        $domain7 = "facebook-update.info" nocase
        $domain8 = "free.dramakorea.asia" nocase
        $domain9 = "getnewandroid.com" nocase
        $domain10 = "hulahope.mooo.com" nocase
        $domain11 = "link.sexyhub.co" nocase
        $domain12 = "mytelkomsel.co" nocase
        $domain13 = "mywealthpop.com" nocase
        $domain14 = "nkpro.lalanews.net" nocase
        $domain15 = "pantheon.tobban.com" nocase
        $domain16 = "people.dohabayt.com" nocase
        $domain17 = "play-mob.org" nocase
        $domain18 = "publiczone.now.im" nocase
        $domain19 = "rcs-demo.hackingteam.it" nocase
        $domain20 = "reflect.dalnet.ca" nocase
        $domain21 = "samsung-update.net" nocase
        $domain22 = "secure.anyurl.org" nocase
        $domain23 = "shrook.mooo.com" nocase
        $domain24 = "telegram-apps.org" nocase
        $domain25 = "update.indoorapps.com" nocase
        $domain26 = "video.sexyhub.co" nocase

    condition:
        any of them
}

rule APT_HAFNIUM {
    meta:
        description = "Indicators associated with APT HAFNIUM"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "TimosaraHackerTerm, Hade ransomware"

    strings:
        $domain0 = "back.estonine.com" nocase
        $domain1 = "bingoshow.xyz" nocase
        $domain2 = "bk.estonine.com" nocase
        $domain3 = "does-no-exist33.estonine.com" nocase
        $domain4 = "e.estonine.com" nocase
        $domain5 = "indicate.estonine.com" nocase
        $domain6 = "inducate.estonine.com" nocase
        $domain7 = "load.estonine.com" nocase
        $domain8 = "log.estonine.com" nocase
        $domain9 = "moon.estonine.com" nocase
        $domain10 = "p.estonine.com" nocase
        $domain11 = "pslog.estonine.com" nocase
        $domain12 = "shelltools-1254394685.cos.ap-shanghai.myqcloud.com" nocase
        $domain13 = "sk.estonine.com" nocase
        $domain14 = "sploit.estonine.com" nocase
        $domain15 = "task.estonine.com" nocase
        $ip16 = "101.37.76.66"

    condition:
        any of them
}

rule APT_HANGOVER {
    meta:
        description = "Indicators associated with APT HANGOVER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "backconfig, monsoon, neon"

    strings:
        $domain0 = "linkrequest.live" nocase
        $domain1 = "matissues.com" nocase
        $domain2 = "unique.fontsupdate.com" nocase
        $ip3 = "212.114.52.20"
        $ip4 = "45.153.241.33"

    condition:
        any of them
}

rule APT_HELLHOUNDS {
    meta:
        description = "Indicators associated with APT HELLHOUNDS"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "08m-srv.daily-share.ns3.name" nocase
        $domain1 = "2fm-srv.daily-share.ns3.name" nocase
        $domain2 = "6cm-srv.daily-share.ns3.name" nocase
        $domain3 = "78m-srv.daily-share.ns3.name" nocase
        $domain4 = "7fm-srv.daily-share.ns3.name" nocase
        $domain5 = "98m-srv.daily-share.ns3.name" nocase
        $domain6 = "acrm-11331.com" nocase
        $domain7 = "ads-tm-glb.click" nocase
        $domain8 = "allowlisted.net" nocase
        $domain9 = "atlas-upd.com" nocase
        $domain10 = "b1m-srv.daily-share.ns3.name" nocase
        $domain11 = "beacon.net.eu.org" nocase
        $domain12 = "c.glb-ru.info" nocase
        $domain13 = "cbox4.ignorelist.com" nocase
        $domain14 = "d5m-srv.daily-share.ns3.name" nocase
        $domain15 = "daily-share.ns3.name" nocase
        $domain16 = "dw-filter.com" nocase
        $domain17 = "ertelecom.org" nocase
        $domain18 = "f-share.duckdns.org" nocase
        $domain19 = "hsdps.cc" nocase
        $domain20 = "lez2yae2.dynamic-dns.net" nocase
        $domain21 = "m-srv.daily-share.ns3.name" nocase
        $domain22 = "maxpatrol.net" nocase
        $domain23 = "mvs05.zyns.com" nocase
        $domain24 = "net-sensors.net" nocase
        $domain25 = "ns1.maxpatrol.net" nocase
        $domain26 = "ns1.net-sensors.net" nocase
        $domain27 = "ns1.webrtc.foo" nocase
        $domain28 = "ns2.maxpatrol.net" nocase
        $domain29 = "ns2.net-sensors.net" nocase
        $domain30 = "ns2.webrtc.foo" nocase
        $domain31 = "ns3.maxpatrol.net" nocase
        $domain32 = "ns4.maxpatrol.net" nocase
        $domain33 = "vcs.dns04.com" nocase
        $domain34 = "webrtc.foo" nocase
        $domain35 = "z-uid.lez2yae2.dynamic-dns.net" nocase

    condition:
        any of them
}

rule APT_HERMIT {
    meta:
        description = "Indicators associated with APT HERMIT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "071790.000webhostapp.com" nocase
        $domain1 = "881.000webhostapp.com" nocase
        $domain2 = "a7788.1apps.com" nocase
        $domain3 = "alabamaok0515.1apps.com" nocase
        $domain4 = "attach10132.1apps.com" nocase
        $domain5 = "charley-online.com" nocase
        $domain6 = "clean.1apps.com" nocase
        $domain7 = "fighiting1013.org" nocase
        $domain8 = "filer1.1apps.com" nocase
        $domain9 = "filer2.1apps.com" nocase
        $domain10 = "hanbosston.000webhostapp.com" nocase
        $domain11 = "s8877.1apps.com" nocase
        $domain12 = "tgbabcrfv.1apps.com" nocase
        $ip13 = "103.249.31.159"
        $ip14 = "5.252.198.93"

    condition:
        any of them
}

rule APT_HEZIRASH {
    meta:
        description = "Indicators associated with APT HEZIRASH"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "hezi-rash.ct.ws" nocase

    condition:
        any of them
}

rule APT_HIGAISA {
    meta:
        description = "Indicators associated with APT HIGAISA"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "api.s2cloud-amazon.com" nocase
        $domain1 = "app-dimensiona.s3.sa-east-1.amazonaws.com" nocase
        $domain2 = "bjj-files-production.s3.sa-east-1.amazonaws.com" nocase
        $domain3 = "comcleanner.info" nocase
        $domain4 = "footracker-statics.s3.sa-east-1.amazonaws.com" nocase
        $domain5 = "goodhk.azurewebsites.net" nocase
        $domain6 = "p-game.s3.sa-east-1.amazonaws.com" nocase
        $domain7 = "s2cloud-amazon.com" nocase
        $domain8 = "sixindent.epizy.com" nocase
        $domain9 = "speedshare.oss-cn-hongkong.aliyuncs.com" nocase
        $domain10 = "xianggang000.oss-cn-hongkong.aliyuncs.com" nocase
        $domain11 = "yitoo.oss-cn-hongkong.aliyuncs.com" nocase
        $domain12 = "zeplin.atwebpages.com" nocase
        $ip13 = "45.76.6.149"

    condition:
        any of them
}

rule APT_HOGFISH {
    meta:
        description = "Indicators associated with APT HOGFISH"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "algorithm.ddnsgeek.com" nocase
        $domain1 = "firefoxcomt.arkouowi.com" nocase
        $domain2 = "friendlysupport.giize.com" nocase
        $domain3 = "update.arkouowi.com" nocase

    condition:
        any of them
}

rule APT_ICEFOG {
    meta:
        description = "Indicators associated with APT ICEFOG"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "01transport.com" nocase
        $domain1 = "applelenovo.com" nocase
        $domain2 = "appst0re.net" nocase
        $domain3 = "aries.epac.to" nocase
        $domain4 = "baagii.sportsnewsa.net" nocase
        $domain5 = "basaa.sportsnewsa.net" nocase
        $domain6 = "benzerold.com" nocase
        $domain7 = "blue-vpn.net" nocase
        $domain8 = "bluesky.zyns.com" nocase
        $domain9 = "bulgaa.sportsnewsa.net" nocase
        $domain10 = "comesafe.com" nocase
        $domain11 = "cospation.net" nocase
        $domain12 = "date.dellnewsup.net" nocase
        $domain13 = "dwm.dnsedc.com" nocase
        $domain14 = "eagleoftajik.dynamic-dns.net" nocase
        $domain15 = "eyellowarm.com" nocase
        $domain16 = "game.sexidude.com" nocase
        $domain17 = "honoroftajik.dynamic-dns.net" nocase
        $domain18 = "https.ikwb.com" nocase
        $domain19 = "kaboolyn.com" nocase
        $domain20 = "kastygost.compress.to" nocase
        $domain21 = "knightpal.com" nocase
        $domain22 = "kyssrcd.pw" nocase
        $domain23 = "laugh.toh.info" nocase
        $domain24 = "mitian123.com" nocase
        $domain25 = "mn.dellnewsup.net" nocase
        $domain26 = "mocus.cospation.net" nocase
        $domain27 = "moonlight.compress.to" nocase
        $domain28 = "news.dellnewsup.net" nocase
        $domain29 = "nicodonald.accesscam.org" nocase
        $domain30 = "niteast.strangled.net" nocase
        $domain31 = "nitec.ns1.name" nocase
        $domain32 = "numnote.com" nocase
        $domain33 = "poff.wha.la" nocase
        $domain34 = "russion.dnsedc.com" nocase
        $domain35 = "skylineqaz.crabdance.com" nocase
        $domain36 = "suverycool.com" nocase
        $domain37 = "tajikmusic.dynamic-dns.net" nocase
        $domain38 = "tajikstantravel.dynamic-dns.net" nocase
        $domain39 = "tele.zyns.com" nocase
        $domain40 = "trendiis.sixth.biz" nocase
        $domain41 = "uzwatersource.dynamic-dns.net" nocase
        $domain42 = "whitebirds.mefound.com" nocase
        $domain43 = "win.dellnewsup.net" nocase
        $domain44 = "xn--uareexcellent-or3qa.kozow.com" nocase
        $domain45 = "ylineqaz-y25ja.crabdance.com" nocase
        $domain46 = "youareexcellent.kozow.com" nocase
        $domain47 = "zaluu.dellnewsup.net" nocase
        $domain48 = "zorsoft.ns1.name" nocase
        $ip49 = "95.179.131.29"

    condition:
        any of them
}

rule APT_ICEPEONY {
    meta:
        description = "Indicators associated with APT ICEPEONY"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "88k8cc.com" nocase
        $domain1 = "d45qomwkl.online" nocase
        $domain2 = "googlesvn.com" nocase
        $domain3 = "k8ccyn.com" nocase
        $domain4 = "k9ccin.com" nocase
        $ip5 = "128.199.70.91"

    condition:
        any of them
}

rule APT_IMPERIALKITTEN {
    meta:
        description = "Indicators associated with APT IMPERIALKITTEN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "IMAPLoader"

    strings:
        $domain0 = "analytics-service.cloud" nocase
        $domain1 = "analytics-service.online" nocase
        $domain2 = "blackcrocodile.online" nocase
        $domain3 = "cdn-analytics.co" nocase
        $domain4 = "cdn.jguery.org" nocase
        $domain5 = "cdnpakage.com" nocase
        $domain6 = "fastanalizer.live" nocase
        $domain7 = "fastanalytics.live" nocase
        $domain8 = "jquery-cdn.online" nocase
        $domain9 = "jquery-code-download.online" nocase
        $domain10 = "jquery-stack.online" nocase
        $domain11 = "prostatistics.live" nocase
        $domain12 = "updatenewnet.com" nocase

    condition:
        any of them
}

rule APT_INDIGOZEBRA {
    meta:
        description = "Indicators associated with APT INDIGOZEBRA"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "2019mfa.com" nocase
        $domain1 = "6z98os.id597.link" nocase
        $domain2 = "cdn.muincxoil.com" nocase
        $domain3 = "google-upgrade.com" nocase
        $domain4 = "help.2019mfa.com" nocase
        $domain5 = "hwyigd.laccessal.org" nocase
        $domain6 = "ictdp.com" nocase
        $domain7 = "id597.link" nocase
        $domain8 = "index.google-upgrade.com" nocase
        $domain9 = "infodocs.kginfocom.com" nocase
        $domain10 = "kginfocom.com" nocase
        $domain11 = "laccessal.org" nocase
        $domain12 = "m.usascd.com" nocase
        $domain13 = "mahallafond.com" nocase
        $domain14 = "mfa-uz.com" nocase
        $domain15 = "mofa.ungov.org" nocase
        $domain16 = "muincxoil.com" nocase
        $domain17 = "ns01-mfa.ungov.org" nocase
        $domain18 = "ousync.kginfocom.com" nocase
        $domain19 = "post.mfa-uz.com" nocase
        $domain20 = "tm.2019mfa.com" nocase
        $domain21 = "ungov.org" nocase
        $domain22 = "update.ictdp.com" nocase
        $domain23 = "usascd.com" nocase
        $domain24 = "uslugi.mahallafond.com" nocase

    condition:
        any of them
}

rule APT_INDRA {
    meta:
        description = "Indicators associated with APT INDRA"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "139.59.89.238"
        $ip1 = "167.172.177.158"
        $ip2 = "172.105.42.64"
        $ip3 = "68.183.79.77"

    condition:
        any of them
}

rule APT_INEDIBLEOCHOTENSE {
    meta:
        description = "Indicators associated with APT INEDIBLEOCHOTENSE"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "eset-endpointantivirus.com" nocase
        $domain1 = "eset-review.com" nocase
        $domain2 = "esetremover.com" nocase
        $domain3 = "esetscanner.com" nocase
        $domain4 = "esetsmart.com" nocase
        $domain5 = "updater-file.xyz" nocase

    condition:
        any of them
}

rule APT_INFY {
    meta:
        description = "Indicators associated with APT INFY"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "foudre, infy"

    strings:
        $domain0 = "017eab31.space" nocase
        $domain1 = "01ead12b.space" nocase
        $domain2 = "0ca0453a.site" nocase
        $domain3 = "149a673e.dynu.net" nocase
        $domain4 = "149a673e.net" nocase
        $domain5 = "149a673e.space" nocase
        $domain6 = "149a673e.top" nocase
        $domain7 = "14c7e2dc.space" nocase
        $domain8 = "15bb747b.site" nocase
        $domain9 = "15ce27c5.site" nocase
        $domain10 = "16e53040.space" nocase
        $domain11 = "177a5c4a.space" nocase
        $domain12 = "17ecf559.site" nocase
        $domain13 = "1cb3c4c0.space" nocase
        $domain14 = "1d4ee030.space" nocase
        $domain15 = "1d8bfc20.space" nocase
        $domain16 = "1f0e7a56.space" nocase
        $domain17 = "23dafa1e.space" nocase
        $domain18 = "2daa46f1.space" nocase
        $domain19 = "32c39cf4.dynu.net" nocase
        $domain20 = "32c39cf4.net" nocase
        $domain21 = "32c39cf4.space" nocase
        $domain22 = "32c39cf4.top" nocase
        $domain23 = "334edefd.dynu.net" nocase
        $domain24 = "334edefd.net" nocase
        $domain25 = "334edefd.space" nocase
        $domain26 = "334edefd.top" nocase
        $domain27 = "341a436d.space" nocase
        $domain28 = "34231ae4.dynu.net" nocase
        $domain29 = "34231ae4.net" nocase
        $domain30 = "34231ae4.space" nocase
        $domain31 = "34231ae4.top" nocase
        $domain32 = "3828b6ed.site" nocase
        $domain33 = "39451f31.space" nocase
        $domain34 = "3a6e08b4.site" nocase
        $domain35 = "3b75d0df.dynu.net" nocase
        $domain36 = "3b75d0df.net" nocase
        $domain37 = "3b75d0df.space" nocase
        $domain38 = "3b75d0df.top" nocase
        $domain39 = "3c6e6571.space" nocase
        $domain40 = "3d9556cf.dynu.net" nocase
        $domain41 = "3d9556cf.net" nocase
        $domain42 = "3d9556cf.space" nocase
        $domain43 = "3d9556cf.top" nocase
        $domain44 = "3e8718c3.site" nocase
        $domain45 = "3f4572f4.site" nocase
        $domain46 = "42a9687b.dynu.net" nocase
        $domain47 = "42a9687b.net" nocase
        $domain48 = "42a9687b.space" nocase
        $domain49 = "42a9687b.top" nocase
        $domain50 = "431d73fb.space" nocase
        $domain51 = "43242a72.dynu.net" nocase
        $domain52 = "43242a72.net" nocase
        $domain53 = "43242a72.space" nocase
        $domain54 = "43242a72.top" nocase
        $domain55 = "43ec206d.top" nocase
        $domain56 = "4449ee6b.dynu.net" nocase
        $domain57 = "4449ee6b.net" nocase
        $domain58 = "4449ee6b.space" nocase
        $domain59 = "4449ee6b.top" nocase
        $domain60 = "45c4ac62.dynu.net" nocase
        $domain61 = "45c4ac62.net" nocase
        $domain62 = "45c4ac62.space" nocase
        $domain63 = "45c4ac62.top" nocase
        $domain64 = "4a926659.dynu.net" nocase
        $domain65 = "4a926659.net" nocase
        $domain66 = "4a926659.space" nocase
        $domain67 = "4a926659.top" nocase
        $domain68 = "4b6955e7.space" nocase
        $domain69 = "4c72e049.dynu.net" nocase
        $domain70 = "4c72e049.net" nocase
        $domain71 = "4c72e049.space" nocase
        $domain72 = "4c72e049.top" nocase
        $domain73 = "4e422fa7.space" nocase
        $domain74 = "4f2f867b.site" nocase
        $domain75 = "5aad7667.space" nocase
        $domain76 = "607d6cdc.space" nocase
        $domain77 = "60ebc5cf.site" nocase
        $domain78 = "61e200d6.space" nocase
        $domain79 = "62c91753.site" nocase
        $domain80 = "63c0d24a.space" nocase
        $domain81 = "68094ac0.space" nocase
        $domain82 = "6bb4f456.space" nocase
        $domain83 = "76ede1bd.space" nocase
        $domain84 = "7ba775ac.site" nocase
        $domain85 = "8447b18a.space" nocase
        $domain86 = "869182ff.site" nocase
        $domain87 = "884efdfb.space" nocase
        $domain88 = "891ec9e9.space" nocase
        $domain89 = "8cc7767f.site" nocase
        $domain90 = "8dceb366.space" nocase
        $domain91 = "8ee5a4e3.site" nocase
        $domain92 = "8fb167c7.space" nocase
        $domain93 = "8fec61fa.space" nocase
        $domain94 = "9155ccba.space" nocase
        $domain95 = "9877fa8b.space" nocase
        $domain96 = "98e38091.space" nocase
        $domain97 = "9c1f58ab.site" nocase
        $domain98 = "9f233843.space" nocase
        $domain99 = "a20af0d2.space" nocase

    condition:
        any of them
}

rule APT_INNAPUT {
    meta:
        description = "Indicators associated with APT INNAPUT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "alert-login-gmail.com" nocase
        $domain1 = "best-online-tv.com" nocase
        $domain2 = "blockhain.name" nocase
        $domain3 = "dockooment.com" nocase
        $domain4 = "docsautentification.com" nocase
        $domain5 = "g000glemail.com" nocase
        $domain6 = "googldraive.com" nocase
        $domain7 = "googledockumets.com" nocase
        $domain8 = "googledraive.com" nocase
        $domain9 = "googlesuport.com" nocase
        $domain10 = "googlmaile.com" nocase
        $domain11 = "googlsupport.com" nocase
        $domain12 = "govreportst.com" nocase
        $domain13 = "iceerd.com" nocase
        $domain14 = "login-googlemail.com" nocase
        $domain15 = "mail-redirect.com.kz" nocase
        $domain16 = "mfa-events.com" nocase
        $domain17 = "msoficceupdate.com" nocase
        $domain18 = "officemicroupdate.com" nocase
        $domain19 = "officeonlaine.com" nocase
        $domain20 = "osc-e.com" nocase
        $domain21 = "pwdrecover.com" nocase
        $domain22 = "suporteng.com" nocase
        $domain23 = "un-booklet.com" nocase
        $domain24 = "update-app.top" nocase
        $domain25 = "us-embassy-report.com" nocase
        $domain26 = "usaid.info" nocase
        $domain27 = "worlwidesupport.top" nocase

    condition:
        any of them
}

rule APT_IRN2 {
    meta:
        description = "Indicators associated with APT IRN2"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "barsupport.org" nocase
        $domain1 = "coldflys.com" nocase
        $domain2 = "forskys.com" nocase
        $domain3 = "shoterup.com" nocase

    condition:
        any of them
}

rule APT_IRONHUSKY {
    meta:
        description = "Indicators associated with APT IRONHUSKY"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "mysterysnail"

    strings:
        $domain0 = "ddspadus.com" nocase
        $domain1 = "http.ddspadus.com" nocase
        $domain2 = "hxxp.ddspadus.com" nocase
        $domain3 = "ipv6.ddspadus.com" nocase
        $domain4 = "nhttp.ddspadus.com" nocase
        $domain5 = "ttp.ddspadus.com" nocase

    condition:
        any of them
}

rule APT_IRONTIGER {
    meta:
        description = "Indicators associated with APT IRONTIGER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "american.blackcmd.com" nocase
        $domain1 = "api.apigmail.com" nocase
        $domain2 = "apigmail.com" nocase
        $domain3 = "backup.darkhero.org" nocase
        $domain4 = "bel.updatawindows.com" nocase
        $domain5 = "binary.update-onlines.org" nocase
        $domain6 = "blackcmd.com" nocase
        $domain7 = "castle.blackcmd.com" nocase
        $domain8 = "centuriosa.info" nocase
        $domain9 = "ctcb.blackcmd.com" nocase
        $domain10 = "darkhero.org" nocase
        $domain11 = "dav.local-test.com" nocase
        $domain12 = "dev.local-test.com" nocase
        $domain13 = "dll.pzchao.com" nocase
        $domain14 = "down.pzchao.com" nocase
        $domain15 = "ftp.google-ana1ytics.com" nocase
        $domain16 = "ga.blackcmd.com" nocase
        $domain17 = "google-ana1ytics.com" nocase
        $domain18 = "helpdesk.blackcmd.com" nocase
        $domain19 = "helpdesk.csc-na.com" nocase
        $domain20 = "helpdesk.hotmail-onlines.com" nocase
        $domain21 = "helpdesk.lnip.org" nocase
        $domain22 = "hotmail-onlines.com" nocase
        $domain23 = "hotmailcontact.net" nocase
        $domain24 = "jobs.hotmail-onlines.com" nocase
        $domain25 = "justufogame.com" nocase
        $domain26 = "laxness-lab.com" nocase
        $domain27 = "lnip.org" nocase
        $domain28 = "local-test.com" nocase
        $domain29 = "login.hansoftupdate.com" nocase
        $domain30 = "long.update-onlines.org" nocase
        $domain31 = "longlong.update-onlines.org" nocase
        $domain32 = "longshadow.dyndns.org" nocase
        $domain33 = "longshadow.update-onlines.org" nocase
        $domain34 = "longykcai.update-onlines.org" nocase
        $domain35 = "lostself.update-onlines.org" nocase
        $domain36 = "mac.navydocument.com" nocase
        $domain37 = "mail.csc-na.com" nocase
        $domain38 = "mantech.updatawindows.com" nocase
        $domain39 = "micr0soft.org" nocase
        $domain40 = "microsoft-outlook.org" nocase
        $domain41 = "mtc.navydocument.com" nocase
        $domain42 = "mtc.update-onlines.org" nocase
        $domain43 = "navydocument.com" nocase
        $domain44 = "news.hotmail-onlines.com" nocase
        $domain45 = "oac.3322.org" nocase
        $domain46 = "ocean.apigmail.com" nocase
        $domain47 = "ocean.local-test.com" nocase
        $domain48 = "pchomeserver.com" nocase
        $domain49 = "rat.pzchao.com" nocase
        $domain50 = "registre.organiccrap.com" nocase
        $domain51 = "security.pomsys.org" nocase
        $domain52 = "services.darkhero.org" nocase
        $domain53 = "sgl.updatawindows.com" nocase
        $domain54 = "shadow.update-onlines.org" nocase
        $domain55 = "sonoco.blackcmd.com" nocase
        $domain56 = "test.local-test.com" nocase
        $domain57 = "test.logmastre.com" nocase
        $domain58 = "up.gtalklite.com" nocase
        $domain59 = "up.pzchao.com" nocase
        $domain60 = "updatawindows.com" nocase
        $domain61 = "update-onlines.org" nocase
        $domain62 = "update.deepsoftupdate.com" nocase
        $domain63 = "update.hancominc.com" nocase
        $domain64 = "update.micr0soft.org" nocase
        $domain65 = "update.pchomeserver.com" nocase
        $domain66 = "urs.blackcmd.com" nocase
        $domain67 = "wang.darkhero.org" nocase
        $domain68 = "webs.local-test.com" nocase
        $domain69 = "word.apigmail.com" nocase
        $domain70 = "wordpress.blackcmd.com" nocase
        $domain71 = "working.blackcmd.com" nocase
        $domain72 = "working.darkhero.org" nocase
        $domain73 = "working.hotmail-onlines.com" nocase
        $domain74 = "www.google-ana1ytics.com" nocase
        $domain75 = "www.trendmicro-update.org" nocase
        $domain76 = "www.update-onlines.org" nocase
        $domain77 = "x.apigmail.com" nocase
        $domain78 = "ykcai.update-onlines.org" nocase
        $domain79 = "ykcailostself.dyndns-free.com" nocase
        $domain80 = "ykcainobody.dyndns.org" nocase
        $domain81 = "zj.blackcmd.com" nocase
        $domain82 = "zll855.gicp.net" nocase
        $domain83 = "zll855.no-ip.info" nocase

    condition:
        any of them
}

rule APT_ISOON {
    meta:
        description = "Indicators associated with APT ISOON"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "i-soon"

    strings:
        $domain0 = "acc.newyorker.cloud" nocase
        $domain1 = "account.newyorker.cloud" nocase
        $domain2 = "asiaic.org" nocase
        $domain3 = "ecoatmosphere.org" nocase
        $domain4 = "grhost.pro" nocase
        $domain5 = "heidrickjobs.com" nocase
        $domain6 = "live.newyorker.cloud" nocase
        $domain7 = "maddmail.site" nocase
        $domain8 = "mobprodetect.live" nocase
        $domain9 = "newvsrch.pro" nocase
        $domain10 = "newyorker.cloud" nocase
        $domain11 = "outlook.newyorker.cloud" nocase
        $domain12 = "ssl.newyorker.cloud" nocase
        $ip13 = "140.82.48.85"
        $ip14 = "149.248.57.11"
        $ip15 = "40.82.48.85"
        $ip16 = "45.77.132.157"
        $ip17 = "95.179.202.21"

    condition:
        any of them
}

rule APT_JUDGMENTPANDA {
    meta:
        description = "Indicators associated with APT JUDGMENTPANDA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-31, bronze vinewood, zirconium"

    strings:
        $domain0 = "api.flushcdn.com" nocase
        $domain1 = "api.hostupoeui.com" nocase
        $domain2 = "api.last-key.com" nocase
        $domain3 = "be-government.com" nocase
        $domain4 = "cdn.microsoft-official.com" nocase
        $domain5 = "const.be-government.com" nocase
        $domain6 = "drmtake.tk" nocase
        $domain7 = "edgecloudc.com" nocase
        $domain8 = "flushcdn.com" nocase
        $domain9 = "gitcloudcache.com" nocase
        $domain10 = "hostupoeui.com" nocase
        $domain11 = "inst.rsnet-devel.com" nocase
        $domain12 = "intranet-rsnet.com" nocase
        $domain13 = "last-key.com" nocase
        $domain14 = "microsoft-products.com" nocase
        $domain15 = "office.microsoft-products.com" nocase
        $domain16 = "offline-microsoft.com" nocase
        $domain17 = "p1.offline-microsoft.com" nocase
        $domain18 = "portal.intranet-rsnet.com" nocase
        $domain19 = "portal.super-encrypt.com" nocase
        $domain20 = "rsnet-devel.com" nocase
        $domain21 = "super-encrypt.com" nocase
        $domain22 = "wshnews.com" nocase
        $domain23 = "yandexpro.net" nocase
        $ip24 = "20.11.11.67"

    condition:
        any of them
}

rule APT_KAPEKA {
    meta:
        description = "Indicators associated with APT KAPEKA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "KnuckleTouch, WrongSens"

    strings:
        $ip0 = "185.38.150.8"
        $ip1 = "185.38.150.8"
        $ip2 = "88.80.148.65"
        $ip3 = "88.80.148.65"
        $ip4 = "88.80.148.65"

    condition:
        any of them
}

rule APT_KARAKURT {
    meta:
        description = "Indicators associated with APT KARAKURT"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "Karakurt Team, Karakurt Lair"

    strings:
        $domain0 = "3f7nxkjway3d223j27lyad7v5cgmyaifesycvmwq7i7cbs23lb6llryd.onion" nocase
        $domain1 = "blog.karakurt.tech" nocase
        $domain2 = "internal.karakurt.tech" nocase
        $domain3 = "karachat.group" nocase
        $domain4 = "karachat.tech" nocase
        $domain5 = "karakurt.co" nocase
        $domain6 = "karakurt.group" nocase
        $domain7 = "karakurt.systems" nocase
        $domain8 = "karakurt.tech" nocase
        $domain9 = "karaleaks.com" nocase
        $domain10 = "omx5iqrdbsoitf3q4xexrqw5r5tfw7vp3vl3li3lfo7saabxazshnead.onion" nocase
        $ip11 = "178.255.220.111"
        $ip12 = "94.156.174.204"
        $ip13 = "94.156.174.204"
        $ip14 = "94.156.174.204"

    condition:
        any of them
}

rule APT_KASABLANKA {
    meta:
        description = "Indicators associated with APT KASABLANKA"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "karabakhtelekom.com" nocase
        $ip1 = "139.84.231.199"
        $ip2 = "193.161.193.99"

    condition:
        any of them
}

rule APT_KE3CHANG {
    meta:
        description = "Indicators associated with APT KE3CHANG"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt15, Ke3chang, Mirage"

    strings:
        $domain0 = "adobeonline.net" nocase
        $domain1 = "andspurs.com" nocase
        $domain2 = "beltsymd.org" nocase
        $domain3 = "buy.babytoy-online.com" nocase
        $domain4 = "buy.healthcare-internet.com" nocase
        $domain5 = "cavanic9.net" nocase
        $domain6 = "center.nmsvillage.com" nocase
        $domain7 = "centrozhlan.com" nocase
        $domain8 = "chart.healthcare-internet.com" nocase
        $domain9 = "compatsec.com" nocase
        $domain10 = "control.mimepanel.org" nocase
        $domain11 = "cv.livehams.com" nocase
        $domain12 = "cyclophilit.com" nocase
        $domain13 = "cyprus-villas.org" nocase
        $domain14 = "daily.huntereim.com" nocase
        $domain15 = "dnsapp.info" nocase
        $domain16 = "dream.zepotac.com" nocase
        $domain17 = "dsmanfacture.privatedns.org" nocase
        $domain18 = "dyname.europemis.com" nocase
        $domain19 = "finance.globaleducat.com" nocase
        $domain20 = "forcan.hausblow.com" nocase
        $domain21 = "goback.strangled.net" nocase
        $domain22 = "grek.freetaxbar.com" nocase
        $domain23 = "halimatoudi.com" nocase
        $domain24 = "info.audioexp.com" nocase
        $domain25 = "inicializacion.com" nocase
        $domain26 = "item.amazonout.com" nocase
        $domain27 = "items.babytoy-online.com" nocase
        $domain28 = "items.burgermap.org" nocase
        $domain29 = "log.autocount.org" nocase
        $domain30 = "login.allionhealth.com" nocase
        $domain31 = "memozilla.org" nocase
        $domain32 = "menorustru.com" nocase
        $domain33 = "menu.thehuguardian.com" nocase
        $domain34 = "micakiz.wikaba.org" nocase
        $domain35 = "misiones.soportesisco.com" nocase
        $domain36 = "newflow.babytoy-online.com" nocase
        $domain37 = "news.memozilla.org" nocase
        $domain38 = "perusmartcity.com" nocase
        $domain39 = "press.premlist.com" nocase
        $domain40 = "promise.miniaturizate.org" nocase
        $domain41 = "rain.nmsvillage.com" nocase
        $domain42 = "ridingduck.com" nocase
        $domain43 = "run.linodepower.com" nocase
        $domain44 = "singa.linodepower.com" nocase
        $domain45 = "store.ufmsecret.org" nocase
        $domain46 = "support.slovakmaps.com" nocase
        $domain47 = "thehuguardian.com" nocase
        $domain48 = "tick.ondemand-sport.com" nocase
        $domain49 = "translate.europemis.com" nocase
        $domain50 = "upcv.inciohali.com" nocase
        $domain51 = "update.adobeonline.net" nocase
        $domain52 = "updateadobeappscom.adobeonline.net" nocase
        $domain53 = "verisims.com" nocase
        $domain54 = "video.memozilla.org" nocase
        $domain55 = "view.beleimprensa.org" nocase
        $domain56 = "wind.deltimesweb.com" nocase
        $domain57 = "www1.sanpaulostat.com" nocase
        $domain58 = "zipcodeterm.com" nocase
        $ip59 = "106.75.99.101"
        $ip60 = "123.60.31.114"
        $ip61 = "172.104.143.75"
        $ip62 = "172.104.143.75"

    condition:
        any of them
}

rule APT_KEYBOY {
    meta:
        description = "Indicators associated with APT KEYBOY"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "keyboy, famoussparrow, pirate panda"

    strings:
        $domain0 = "about.jkub.com" nocase
        $domain1 = "adobehomework.com" nocase
        $domain2 = "ak.buycheap.cn" nocase
        $domain3 = "amazoncdns.com" nocase
        $domain4 = "ap.missmichiko.com" nocase
        $domain5 = "api.cnicchina.com" nocase
        $domain6 = "athenatechlabs.com" nocase
        $domain7 = "auth.boxlibraries.com" nocase
        $domain8 = "awsdns-531.com" nocase
        $domain9 = "backus.myftp.name" nocase
        $domain10 = "blog.techmersion.com" nocase
        $domain11 = "broadmediacloud.com" nocase
        $domain12 = "buycheap.cn" nocase
        $domain13 = "c11r.awsdns-531.com" nocase
        $domain14 = "cache10.newsfreecloud.com" nocase
        $domain15 = "cachecloud.cloudflaresrv.com" nocase
        $domain16 = "cas04.awsdns-531.com" nocase
        $domain17 = "cdglobalclouds.com" nocase
        $domain18 = "cdn.kkxx888666.com" nocase
        $domain19 = "cdn101.cloudflaresrv.com" nocase
        $domain20 = "cdn181.awsdns-531.com" nocase
        $domain21 = "cloudflaresrv.com" nocase
        $domain22 = "cloudshappen.com" nocase
        $domain23 = "cloudsrv.cloudfrontsrv.com" nocase
        $domain24 = "cnicchina.com" nocase
        $domain25 = "credits.offices-analytics.com" nocase
        $domain26 = "dbacloudsupport.com" nocase
        $domain27 = "de.huseinhbz.click" nocase
        $domain28 = "dpponline.trickip.org" nocase
        $domain29 = "eleven.mypop3.org" nocase
        $domain30 = "emv1.cdglobalclouds.com" nocase
        $domain31 = "emv1.techmersion.com" nocase
        $domain32 = "euphemismscase.site" nocase
        $domain33 = "flarecastdns.com" nocase
        $domain34 = "ftp.techmersion.com" nocase
        $domain35 = "ge.huseinhbz.click" nocase
        $domain36 = "global.techmersion.com" nocase
        $domain37 = "globalnetzone.b-cdn.net" nocase
        $domain38 = "helpdesk.athenatechlabs.com" nocase
        $domain39 = "helpdesk.cloudshappen.com" nocase
        $domain40 = "huseinhbz.click" nocase
        $domain41 = "images.dbacloudsupport.com" nocase
        $domain42 = "johannesburghotel.net" nocase
        $domain43 = "jupiter.qpoe.com" nocase
        $domain44 = "kidshomeworkabc.global.ssl.fastly.net" nocase
        $domain45 = "kkxx888666.com" nocase
        $domain46 = "laishi.ddns.net" nocase
        $domain47 = "llnw-dd.awsdns-531.com" nocase
        $domain48 = "lync.realtxholdem.com" nocase
        $domain49 = "mail.euphemismscase.site" nocase
        $domain50 = "mail2-0da8aa1c.oxcdntech.com" nocase
        $domain51 = "mila1314.25u.com" nocase
        $domain52 = "mila1314.4dq.com" nocase
        $domain53 = "mila1314.ddns.info" nocase
        $domain54 = "missmichiko.com" nocase
        $domain55 = "ms119.newsfreecloud.com" nocase
        $domain56 = "myinfo.ocry.com" nocase
        $domain57 = "myzinfo.myz.info" nocase
        $domain58 = "newsfreecloud.com" nocase
        $domain59 = "nodtecloud.com" nocase
        $domain60 = "ns.starkaero.com" nocase
        $domain61 = "ns101.awsdns-531.com" nocase
        $domain62 = "ns108.cloudshappen.com" nocase
        $domain63 = "offices-analytics.com" nocase
        $domain64 = "oldape.25u.com" nocase
        $domain65 = "oldape.4dq.com" nocase
        $domain66 = "opengl.cloudshappen.com" nocase
        $domain67 = "oxcdntech.com" nocase
        $domain68 = "pay.johannesburghotel.net" nocase
        $domain69 = "portal.cdglobalclouds.com" nocase
        $domain70 = "portal.sppokemon.com" nocase
        $domain71 = "portal.techmersion.com" nocase
        $domain72 = "rdmail.redcrossco.com" nocase
        $domain73 = "realtxholdem.com" nocase
        $domain74 = "redcrossco.com" nocase
        $domain75 = "redsquare.redcrossco.com" nocase
        $domain76 = "resource.offices-analytics.com" nocase
        $domain77 = "services.offices-analytics.com" nocase
        $domain78 = "soffice.offices-analytics.com" nocase
        $domain79 = "sppokemon.com" nocase
        $domain80 = "ssl3.awsdns-531.com" nocase
        $domain81 = "starkaero.com" nocase
        $domain82 = "supports.dbacloudsupport.com" nocase
        $domain83 = "supports.flarecastdns.com" nocase
        $domain84 = "svn.truecdnnetwork.com" nocase
        $domain85 = "techmersion.com" nocase
        $domain86 = "tibetvoices.com" nocase
        $domain87 = "tranning.redcrossco.com" nocase
        $domain88 = "truecdnnetwork.com" nocase
        $domain89 = "zmail.broadmediacloud.com" nocase
        $ip90 = "101.32.36.76"
        $ip91 = "106.53.120.204"
        $ip92 = "114.251.216.125"
        $ip93 = "118.195.161.141"
        $ip94 = "118.195.161.141"
        $ip95 = "132.232.92.218"
        $ip96 = "134.175.197.144"
        $ip97 = "150.109.114.190"
        $ip98 = "155.138.155.181"
        $ip99 = "159.75.144.13"
        $ip100 = "159.75.81.151"
        $ip101 = "159.75.83.212"
        $ip102 = "185.20.187.10"
        $ip103 = "212.182.121.97"
        $ip104 = "219.225.109.246"
        $ip105 = "43.129.177.152"
        $ip106 = "43.134.194.237"
        $ip107 = "43.154.74.7"
        $ip108 = "43.154.85.5"
        $ip109 = "43.154.88.192"
        $ip110 = "45.76.218.247"
        $ip111 = "45.77.178.47"
        $ip112 = "49.232.142.8"
        $ip113 = "82.156.178.135"
        $ip114 = "82.156.178.135"
        $ip115 = "82.157.51.214"
        $ip116 = "82.157.62.199"

    condition:
        any of them
}

rule APT_KIMSUKY {
    meta:
        description = "Indicators associated with APT KIMSUKY"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "APT-C-55, Black Banshee, Velvet Chollima"

    strings:
        $domain0 = "00701111.000webhostapp.com" nocase
        $domain1 = "00a7c185.duckdns.org" nocase
        $domain2 = "00mknjbhy.dynv6.net" nocase
        $domain3 = "00pr43.picid1fdl6.dynv6.net" nocase
        $domain4 = "01nservercc.cfd" nocase
        $domain5 = "01onlinen.cfd" nocase
        $domain6 = "022hucku25u.dns.navy" nocase
        $domain7 = "02nservercc.cfd" nocase
        $domain8 = "02onlinen.cfd" nocase
        $domain9 = "03nservercc.cfd" nocase
        $domain10 = "03onlinen.cfd" nocase
        $domain11 = "04nservercc.cfd" nocase
        $domain12 = "04onlinen.cfd" nocase
        $domain13 = "059879e5-b2e8-4f58-aa46-95f69d92aa34.random.onlinenhiscomservice.store" nocase
        $domain14 = "059879e5-b2e8-4f58-aa46-95f69d92aa34.random.voranstaks.shop" nocase
        $domain15 = "05c0.nkfumxgqxd.v6.rocks" nocase
        $domain16 = "05nservercc.cfd" nocase
        $domain17 = "05onlinen.cfd" nocase
        $domain18 = "06nservercc.cfd" nocase
        $domain19 = "06onlinen.cfd" nocase
        $domain20 = "0751u9n4lg.v6.rocks" nocase
        $domain21 = "07nservercc.cfd" nocase
        $domain22 = "07onlinen.cfd" nocase
        $domain23 = "086k3a.93vf4b71cv.dynv6.net" nocase
        $domain24 = "08nservercc.cfd" nocase
        $domain25 = "08onlinen.cfd" nocase
        $domain26 = "090.apollo-page.kro.kr" nocase
        $domain27 = "090.gov5nikisa.kro.kr" nocase
        $domain28 = "09nservercc.cfd" nocase
        $domain29 = "09onlinen.cfd" nocase
        $domain30 = "0a1fi7nsne.dynv6.net" nocase
        $domain31 = "0c50zrvnoi.v6.rocks" nocase
        $domain32 = "0dj87hc.v6.rocks" nocase
        $domain33 = "0g25r94p96.v6.army" nocase
        $domain34 = "0grde8ebon.dns.army" nocase
        $domain35 = "0jr87375qt.v6.navy" nocase
        $domain36 = "0knw2300.mypressonline.com" nocase
        $domain37 = "0mvkf48r.v6.army" nocase
        $domain38 = "0reudifh9384.dynv6.net" nocase
        $domain39 = "0s2snxin4t.v6.navy" nocase
        $domain40 = "0sv8.qiz172u9i01.dns.army" nocase
        $domain41 = "0t3ofn4r21.dns.navy" nocase
        $domain42 = "0twjc657tu.v6.navy" nocase
        $domain43 = "0vjdf88.dynv6.net" nocase
        $domain44 = "0vym.mailcorp.eu" nocase
        $domain45 = "0x0.care" nocase
        $domain46 = "1-z.never.com.ru" nocase
        $domain47 = "1.aenco.kro.kr" nocase
        $domain48 = "100000recipe.com" nocase
        $domain49 = "100nservercc.cfd" nocase
        $domain50 = "102c928da265b.duckdns.org" nocase
        $domain51 = "107-189-24-28.cprapid.com" nocase
        $domain52 = "107.189.24.28.sslip.io" nocase
        $domain53 = "10nservercc.cfd" nocase
        $domain54 = "10onlinen.cfd" nocase
        $domain55 = "112-216-240-98.softether.net" nocase
        $domain56 = "11nservercc.cfd" nocase
        $domain57 = "11onlinen.cfd" nocase
        $domain58 = "12-ko-official.com" nocase
        $domain59 = "1213rt.atwebpages.com" nocase
        $domain60 = "123.apollo-page.n-e.kr" nocase
        $domain61 = "12e9w4hp1f.v6.army" nocase
        $domain62 = "12nservercc.cfd" nocase
        $domain63 = "12onlinen.cfd" nocase
        $domain64 = "139.149amdoc-hometax.mydns.bz" nocase
        $domain65 = "139.149aodoc-hometax.mydns.bz" nocase
        $domain66 = "13nservercc.cfd" nocase
        $domain67 = "13onlinen.cfd" nocase
        $domain68 = "13udm.v6.navy" nocase
        $domain69 = "149amdoc-hometax.mydns.bz" nocase
        $domain70 = "149aodoc-hometax.mydns.bz" nocase
        $domain71 = "14nservercc.cfd" nocase
        $domain72 = "14onlinen.cfd" nocase
        $domain73 = "150edoc.npsdkimrecord.mydns.bz" nocase
        $domain74 = "150nhsmobiles.mydns.bz" nocase
        $domain75 = "150userinfo.nhsmobiles.mydns.bz" nocase
        $domain76 = "152.32.139.149amdoc-hometax.mydns.bz" nocase
        $domain77 = "152.32.139.149aodoc-hometax.mydns.bz" nocase
        $domain78 = "158-247-224-102.nip.io" nocase
        $domain79 = "158.247.210.58n-cloud.nauth-ips.mydns.vc" nocase
        $domain80 = "158.247.210.58n-store.ips-nidlg.mydns.bz" nocase
        $domain81 = "158.247.219.150edoc.npsdkimrecord.mydns.bz" nocase
        $domain82 = "158.247.219.150nhsmobiles.mydns.bz" nocase
        $domain83 = "158.247.219.150userinfo.nhsmobiles.mydns.bz" nocase
        $domain84 = "15dhyfituhivoivjjgijrtjtgg.cfd" nocase
        $domain85 = "15fuerouhrgiurtituigjtug.cfd" nocase
        $domain86 = "15hjdgvfdjbvunghghod.cfd" nocase
        $domain87 = "15jhguerhguyogjopgoff.cfd" nocase
        $domain88 = "15nservercc.cfd" nocase
        $domain89 = "15onlinen.cfd" nocase
        $domain90 = "15ygfyerfgyufhsdgfyegf.cfd" nocase
        $domain91 = "15yufibeuiohuireiogjrgji.cfd" nocase
        $domain92 = "1636.site" nocase
        $domain93 = "1661-0241-call.site" nocase
        $domain94 = "1666-7797.site" nocase
        $domain95 = "16nservercc.cfd" nocase
        $domain96 = "16onlinen.cfd" nocase
        $domain97 = "17ej3.t1wcwln96d.v6.rocks" nocase
        $domain98 = "17nservercc.cfd" nocase
        $domain99 = "17onlinen.cfd" nocase
        $ip100 = "101.36.114.235"
        $ip101 = "103.20.235.113"
        $ip102 = "103.76.228.204"
        $ip103 = "104.168.145.83"
        $ip104 = "104.194.152.22"
        $ip105 = "104.194.152.251"
        $ip106 = "104.194.152.251"
        $ip107 = "104.36.229.179"
        $ip108 = "104.36.229.179"
        $ip109 = "107.148.71.88"
        $ip110 = "107.189.16.65"
        $ip111 = "109.248.151.179"
        $ip112 = "115.193.38.156"
        $ip113 = "115.195.112.167"
        $ip114 = "115.197.193.142"
        $ip115 = "116.202.99.218"
        $ip116 = "118.194.248.246"
        $ip117 = "121.183.134.113"
        $ip118 = "121.183.134.113"
        $ip119 = "121.183.134.113"
        $ip120 = "121.66.72.110"
        $ip121 = "123.58.200.110"
        $ip122 = "125.118.95.227"
        $ip123 = "125.136.67.99"
        $ip124 = "138.197.235.123"
        $ip125 = "138.68.112.220"
        $ip126 = "139.208.63.224"
        $ip127 = "141.164.41.17"
        $ip128 = "152.32.138.120"
        $ip129 = "152.89.247.57"
        $ip130 = "153.75.233.17"
        $ip131 = "156.224.22.247"
        $ip132 = "158.247.238.155"
        $ip133 = "159.100.6.137"
        $ip134 = "161.97.113.34"
        $ip135 = "162.216.114.133"
        $ip136 = "162.245.188.225"
        $ip137 = "172.93.201.248"
        $ip138 = "172.93.201.248"
        $ip139 = "173.214.170.58"
        $ip140 = "183.105.66.48"
        $ip141 = "185.224.137.164"
        $ip142 = "185.235.128.114"
        $ip143 = "192.186.142.74"
        $ip144 = "192.236.154.125"
        $ip145 = "203.245.0.121"
        $ip146 = "206.206.127.152"
        $ip147 = "206.206.127.152"
        $ip148 = "206.206.127.152"
        $ip149 = "206.206.127.152"

    condition:
        any of them
}

rule APT_KUN3 {
    meta:
        description = "Indicators associated with APT KUN3"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-k-un3"

    strings:
        $domain0 = "28dg.com" nocase
        $domain1 = "360-browser.com" nocase
        $domain2 = "360edge.cn" nocase
        $domain3 = "7s.pc-kakaocorp.com" nocase
        $domain4 = "8-210-67-136.cprapid.com" nocase
        $domain5 = "88886.shop" nocase
        $domain6 = "aaronbrender.com" nocase
        $domain7 = "aaronbrender.net" nocase
        $domain8 = "aaronbrender.org" nocase
        $domain9 = "addguard.cn" nocase
        $domain10 = "adzuki.us" nocase
        $domain11 = "af-whatsapp.com" nocase
        $domain12 = "agarpowder.us" nocase
        $domain13 = "andydeitrich.com" nocase
        $domain14 = "anzhihui.net" nocase
        $domain15 = "api.hami888.com" nocase
        $domain16 = "app-kuake.com.cn" nocase
        $domain17 = "app-quark.com.cn" nocase
        $domain18 = "app.zyxhlh.com" nocase
        $domain19 = "approved-medical.com" nocase
        $domain20 = "apps-aisi.com" nocase
        $domain21 = "apps-helloworld.com" nocase
        $domain22 = "apps-huorong.com" nocase
        $domain23 = "apps-i4.com" nocase
        $domain24 = "apps-kakaocorp.com" nocase
        $domain25 = "apps-kakaotalk.com" nocase
        $domain26 = "apps-kuaiiian.com" nocase
        $domain27 = "apps-oray.com" nocase
        $domain28 = "apps-quark.com" nocase
        $domain29 = "apps-sougoupinyin.com" nocase
        $domain30 = "apps-tencent.com" nocase
        $domain31 = "apps-v2rayn.com" nocase
        $domain32 = "apps-winrar.com" nocase
        $domain33 = "apps-wps.com" nocase
        $domain34 = "apps-xiangrikui.com" nocase
        $domain35 = "appx-wps.com" nocase
        $domain36 = "aps-wps.com" nocase
        $domain37 = "arthauscustomworks.com" nocase
        $domain38 = "arunstennisacademy.com" nocase
        $domain39 = "ateliersaaka.com" nocase
        $domain40 = "attacklive.com" nocase
        $domain41 = "awq-line.com" nocase
        $domain42 = "backlinkmate.com" nocase
        $domain43 = "baobeimiao.com" nocase
        $domain44 = "bbbbbd.cn" nocase
        $domain45 = "beanmachineatx.com" nocase
        $domain46 = "beijingjiawenkeji.com" nocase
        $domain47 = "beijingzhongmingsheng.com" nocase
        $domain48 = "beliefforce.com" nocase
        $domain49 = "bing-sogou.com" nocase
        $domain50 = "biz-wps.com" nocase
        $domain51 = "bjjfyyfk.com" nocase
        $domain52 = "blackfale.xyz" nocase
        $domain53 = "brwslapp.com" nocase
        $domain54 = "bvfullstack.net" nocase
        $domain55 = "bwpongwv.cn" nocase
        $domain56 = "bwsc668.com" nocase
        $domain57 = "bza.com" nocase
        $domain58 = "bzwslapp.com" nocase
        $domain59 = "cashotc.com" nocase
        $domain60 = "catherinekluge.com" nocase
        $domain61 = "chachazaimai.com" nocase
        $domain62 = "charleswboyer.com" nocase
        $domain63 = "cheap-meds-online.com" nocase
        $domain64 = "chromiumx-360.cn" nocase
        $domain65 = "clash55.com" nocase
        $domain66 = "clash99.com" nocase
        $domain67 = "clashdown.link" nocase
        $domain68 = "clashdown.today" nocase
        $domain69 = "cn-kuake.com.cn" nocase
        $domain70 = "cn-quark.com.cn" nocase
        $domain71 = "com-inicioportal.com" nocase
        $domain72 = "css-line.com" nocase
        $domain73 = "cym-line.com" nocase
        $domain74 = "cz.czsiss.icu" nocase
        $domain75 = "czsiss.icu" nocase
        $domain76 = "d1-myvip-mirrors.avadev.cn" nocase
        $domain77 = "daily-pharm.com" nocase
        $domain78 = "darthbeach.com" nocase
        $domain79 = "davessprinklerrepair.com" nocase
        $domain80 = "dfeldman.org" nocase
        $domain81 = "dianbaoo.com" nocase
        $domain82 = "dingze.com.cn" nocase
        $domain83 = "djwslapp.com" nocase
        $domain84 = "dkalca11.asia" nocase
        $domain85 = "down.letsvpnc.com" nocase
        $domain86 = "download.i96l6.top" nocase
        $domain87 = "drggn.net" nocase
        $domain88 = "dslchurch.org" nocase
        $domain89 = "dtm2.com" nocase
        $domain90 = "ducthanging.com" nocase
        $domain91 = "ductset.com" nocase
        $domain92 = "e-quark.com.cn" nocase
        $domain93 = "elocreations.com" nocase
        $domain94 = "emilyklinepianostudio.com" nocase
        $domain95 = "entermycodes.com" nocase
        $domain96 = "equanimgrc.com" nocase
        $domain97 = "eu-clinic.com" nocase
        $domain98 = "exklusive-artikel.com" nocase
        $domain99 = "falkenbergsrasfjaderfaklubb.com" nocase
        $ip100 = "137.220.140.4"
        $ip101 = "156.251.17.147"
        $ip102 = "43.248.172.115"
        $ip103 = "43.248.172.115"
        $ip104 = "45.204.207.244"

    condition:
        any of them
}

rule APT_LAZARUS {
    meta:
        description = "Indicators associated with APT LAZARUS"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "appleworm, apt-c-26, apt-q-1"

    strings:
        $domain0 = "0927.vercel.app" nocase
        $domain1 = "0xraiseup.com" nocase
        $domain2 = "1-73g.pages.dev" nocase
        $domain3 = "118274-zoomid.com" nocase
        $domain4 = "11stnft.click" nocase
        $domain5 = "1215.vercel.app" nocase
        $domain6 = "123fisd.naveicoipg.online" nocase
        $domain7 = "129react.pages.dev" nocase
        $domain8 = "15248636.site" nocase
        $domain9 = "1688dsj.com" nocase
        $domain10 = "17.docsend.store" nocase
        $domain11 = "172-86-114-141.dal.priv.octovpn.net" nocase
        $domain12 = "172-86-114-170.dal.priv.octovpn.net" nocase
        $domain13 = "172-86-89-213.cprapid.com" nocase
        $domain14 = "1drvmicrosoft.com" nocase
        $domain15 = "1winfans.com" nocase
        $domain16 = "247l.net" nocase
        $domain17 = "260120.vercel.app" nocase
        $domain18 = "2ab9.watashinonegai.ru" nocase
        $domain19 = "2daojnjnp666jla6.dropfile.online" nocase
        $domain20 = "3.143.24.91.sslip.io" nocase
        $domain21 = "360scanner.store" nocase
        $domain22 = "360share.pro" nocase
        $domain23 = "3la6ol.net" nocase
        $domain24 = "49rjaf1fgrlzl1t82dpxmiqmyeedl4kku5y3hjvanjleyhpo3pjmbn23q0.pages.dev" nocase
        $domain25 = "4bjt2rceijktwedi.onion" nocase
        $domain26 = "4w9h8ps9.naveicoipa.tech" nocase
        $domain27 = "4w9h8ps9.naveicoipc.tech" nocase
        $domain28 = "5l.securemypc.xyz" nocase
        $domain29 = "6la0cwds.naveicoiph.online" nocase
        $domain30 = "7xvc.meeting-central.online" nocase
        $domain31 = "7xvc.meeting-zone.online" nocase
        $domain32 = "7xvc.roomconnect.online" nocase
        $domain33 = "7xvc.virtual-collab.online" nocase
        $domain34 = "8190ocvswfyd57v5.docsend.online" nocase
        $domain35 = "91.90.121.87.sslip.io" nocase
        $domain36 = "9yxqida1b.naveicoiph.online" nocase
        $domain37 = "a.videotalks.site" nocase
        $domain38 = "aat1pbil.naveicoipg.online" nocase
        $domain39 = "abc.meeting-central.online" nocase
        $domain40 = "abc.meeting-zone.online" nocase
        $domain41 = "abc.preconnection.online" nocase
        $domain42 = "abc.roomconnect.online" nocase
        $domain43 = "abilityscan360.com" nocase
        $domain44 = "abs.twitter.expublic.linkpc.net" nocase
        $domain45 = "access.support.general-meet.site" nocase
        $domain46 = "accounts.ceinbase.com" nocase
        $domain47 = "acoustickoala.com" nocase
        $domain48 = "acroadovw.com" nocase
        $domain49 = "activity-179384736.site" nocase
        $domain50 = "activity-permission.online" nocase
        $domain51 = "additional.work.gd" nocase
        $domain52 = "additionalpublic.work.gd" nocase
        $domain53 = "addrcheck.corecheckmailsrv.com" nocase
        $domain54 = "ade.dropfile.online" nocase
        $domain55 = "admescolassystemf.com" nocase
        $domain56 = "admin-8jy8o7jbg.vercel.sh" nocase
        $domain57 = "admin.alwayswelcome.online" nocase
        $domain58 = "admin.chrome-browser.cloud" nocase
        $domain59 = "admin.docsend.online" nocase
        $domain60 = "admin.docsend.site" nocase
        $domain61 = "admin.drop-box.store" nocase
        $domain62 = "admin.dropfile.online" nocase
        $domain63 = "admin.echelonfnd.io" nocase
        $domain64 = "admin.general-meet.site" nocase
        $domain65 = "admin.luckyguys.cloud" nocase
        $domain66 = "admin.luckyguys.site" nocase
        $domain67 = "admin.meeting-central.online" nocase
        $domain68 = "admin.meeting-zone.online" nocase
        $domain69 = "admin.rohapowers.com" nocase
        $domain70 = "admin.support.general-meet.site" nocase
        $domain71 = "admin0.docsend.store" nocase
        $domain72 = "adnoc.sbs" nocase
        $domain73 = "aduresi.com" nocase
        $domain74 = "advantims.com" nocase
        $domain75 = "advisor-ecareerflare.pages.dev" nocase
        $domain76 = "advisorflux.com" nocase
        $domain77 = "advisorflux.pages.dev" nocase
        $domain78 = "advisornetic.com" nocase
        $domain79 = "advisoryfit.com" nocase
        $domain80 = "advisoryfit.pages.dev" nocase
        $domain81 = "advisorygrid.com" nocase
        $domain82 = "adzjvazj.naveicoipg.online" nocase
        $domain83 = "ae-zoom.us" nocase
        $domain84 = "ae-zooom-hegne-meetingsfromf6758s.pages.dev" nocase
        $domain85 = "aeroplans.info" nocase
        $domain86 = "aes-secure.net" nocase
        $domain87 = "affiliate.support.general-meet.site" nocase
        $domain88 = "africamall.chat" nocase
        $domain89 = "ag.centoservices.cz" nocase
        $domain90 = "agafilime.com" nocase
        $domain91 = "agora.assessintel.com" nocase
        $domain92 = "ai.coinhouse360.com" nocase
        $domain93 = "aiagentnow.online" nocase
        $domain94 = "aideck.net" nocase
        $domain95 = "aigtech.dev" nocase
        $domain96 = "aihealthchains.com" nocase
        $domain97 = "aionedev.best" nocase
        $domain98 = "aixstore.info" nocase
        $domain99 = "ajileuowl.dliklone.online" nocase
        $ip100 = "100.51.175.254"
        $ip101 = "103.106.67.63"
        $ip102 = "103.106.67.63"
        $ip103 = "103.106.67.63"
        $ip104 = "103.205.179.4"
        $ip105 = "103.231.75.101"
        $ip106 = "103.35.188.48"
        $ip107 = "103.35.188.48"
        $ip108 = "103.35.189.107"
        $ip109 = "103.35.189.107"
        $ip110 = "103.65.230.100"
        $ip111 = "104.168.136.24"
        $ip112 = "104.168.151.116"
        $ip113 = "104.168.151.34"
        $ip114 = "104.168.157.45"
        $ip115 = "104.168.157.45"
        $ip116 = "104.168.165.165"
        $ip117 = "104.168.165.165"
        $ip118 = "104.168.165.173"
        $ip119 = "104.168.165.173"
        $ip120 = "104.168.165.203"
        $ip121 = "104.168.165.203"
        $ip122 = "104.168.172.20"
        $ip123 = "104.168.198.145"
        $ip124 = "104.168.203.159"
        $ip125 = "104.168.203.159"
        $ip126 = "104.192.42.117"
        $ip127 = "104.194.133.88"
        $ip128 = "104.194.133.88"
        $ip129 = "104.194.153.144"
        $ip130 = "104.194.153.144"
        $ip131 = "104.194.153.144"
        $ip132 = "104.217.163.61"
        $ip133 = "104.232.71.7"
        $ip134 = "107.172.197.175"
        $ip135 = "107.175.172.129"
        $ip136 = "107.189.16.122"
        $ip137 = "107.189.16.122"
        $ip138 = "107.189.16.176"
        $ip139 = "107.189.16.176"
        $ip140 = "107.189.20.152"
        $ip141 = "107.189.20.152"
        $ip142 = "107.189.22.20"
        $ip143 = "107.189.22.20"
        $ip144 = "107.189.22.20"
        $ip145 = "107.189.24.80"
        $ip146 = "107.189.24.80"
        $ip147 = "107.189.25.109"
        $ip148 = "107.189.25.109"
        $ip149 = "107.6.12.135"

    condition:
        any of them
}

rule APT_LAZYSCRIPTER {
    meta:
        description = "Indicators associated with APT LAZYSCRIPTER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bsjsiq3ytpt3efsn6wnu3pukxil6q6plty6m6dcz.duckdns.org" nocase
        $domain1 = "gowaymevps.xyz" nocase
        $domain2 = "gowaymevpslink1.xyz" nocase
        $domain3 = "gowaymevpslink2.xyz" nocase
        $domain4 = "gowaymevpslink3.xyz" nocase
        $domain5 = "gowaymevpslink4.xyz" nocase
        $domain6 = "gowaymevpslink5.xyz" nocase
        $domain7 = "iatassl-telechargementsecurity.duckdns.org" nocase
        $domain8 = "internetexploraldon.sytes.net" nocase
        $domain9 = "jbizgsvhzj22evqon9ezz8bmbupp1s6cprmriam1.duckdns.org" nocase
        $domain10 = "milla.publicvm.com" nocase
        $domain11 = "saqicpcgflrlgxgoxxzkbfrjuisbkozeqrmthrzo.duckdns.org" nocase
        $domain12 = "securessl.fit" nocase
        $domain13 = "smscs.publicvm.com" nocase
        $domain14 = "stub.ignorelist.com" nocase
        $domain15 = "u1153246fov.ha004.t.justns.ru" nocase
        $domain16 = "varifsecuripass.duckdns.org" nocase
        $domain17 = "vistacp-enhance.duckdns.org" nocase
        $ip18 = "185.81.157.186"
        $ip19 = "45.91.92.112"

    condition:
        any of them
}

rule APT_LEAFMINER {
    meta:
        description = "Indicators associated with APT LEAFMINER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "adobe-flash.us" nocase
        $domain1 = "adobe-plugin.bid" nocase
        $domain2 = "ilhost.in" nocase
        $domain3 = "iqhost.us" nocase
        $domain4 = "microsoft-office-free-templates-download.btc-int.in" nocase
        $domain5 = "microsoft-office-free-templates.in" nocase
        $domain6 = "offiice365.us" nocase

    condition:
        any of them
}

rule APT_LIBRARIANGHOULS {
    meta:
        description = "Indicators associated with APT LIBRARIANGHOULS"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "rare werewolf"

    strings:
        $domain0 = "4t-niagara.com" nocase
        $domain1 = "4tniagara.com" nocase
        $domain2 = "9mmenergy.biz" nocase
        $domain3 = "accouts-verification.ru" nocase
        $domain4 = "acountservices.nl" nocase
        $domain5 = "acountservices.online" nocase
        $domain6 = "aemiliuszathe.nl" nocase
        $domain7 = "aeternus.be" nocase
        $domain8 = "alcor-as.com" nocase
        $domain9 = "allroundvideomedia.nl" nocase
        $domain10 = "almaz-aero.site" nocase
        $domain11 = "amaryllisclinic.nl" nocase
        $domain12 = "amorapersoneel.nl" nocase
        $domain13 = "anyhostings.ru" nocase
        $domain14 = "anyinfos.ru" nocase
        $domain15 = "aoffices.ru" nocase
        $domain16 = "ardensonlineconsultancyfirm.com" nocase
        $domain17 = "artichi.be" nocase
        $domain18 = "artonlinemarketing.nl" nocase
        $domain19 = "autodegroenehoek.nl" nocase
        $domain20 = "autoopkoperbenny.be" nocase
        $domain21 = "autotificate.com" nocase
        $domain22 = "aviatronika.online" nocase
        $domain23 = "barbershopwbd.nl" nocase
        $domain24 = "batwoman-fashion.nl" nocase
        $domain25 = "beeldspraakfotografie.nl" nocase
        $domain26 = "berkelgame.com" nocase
        $domain27 = "bewustopvoedenenbegeleiden.com" nocase
        $domain28 = "bharatsingh-logistics.nl" nocase
        $domain29 = "biesbeauty.nl" nocase
        $domain30 = "bijbelseexpressie.nl" nocase
        $domain31 = "blijlekkernij.nl" nocase
        $domain32 = "bloomakay.be" nocase
        $domain33 = "bmapps.org" nocase
        $domain34 = "boefjes.nl" nocase
        $domain35 = "boelit-pvlog.be" nocase
        $domain36 = "bouwwerkennoten.be" nocase
        $domain37 = "broodjesboutique.nl" nocase
        $domain38 = "bulletpointband.com" nocase
        $domain39 = "cafestationskoffiehuis.nl" nocase
        $domain40 = "camperbilly.nl" nocase
        $domain41 = "camperreiseuropa.nl" nocase
        $domain42 = "careforhealing.com" nocase
        $domain43 = "cc-int.online" nocase
        $domain44 = "center-mail.ru" nocase
        $domain45 = "choosingchange.nl" nocase
        $domain46 = "cirkelvoordeelshop.nl" nocase
        $domain47 = "claud-mail.ru" nocase
        $domain48 = "climatexperts.be" nocase
        $domain49 = "codevalley.nl" nocase
        $domain50 = "dagboekvaneenoverlever.nl" nocase
        $domain51 = "dakzaken.nl" nocase
        $domain52 = "daniel-stunnenberg.nl" nocase
        $domain53 = "danonnapinuccia.nl" nocase
        $domain54 = "datagiants.be" nocase
        $domain55 = "daydrinkingdisco.com" nocase
        $domain56 = "deauthorization.online" nocase
        $domain57 = "deboswachteramsterdam.nl" nocase
        $domain58 = "dedienstenpraktijk.nl" nocase
        $domain59 = "degrotewebwinkel.nl" nocase
        $domain60 = "dennisbaptist.com" nocase
        $domain61 = "dentaldegroenehoek.nl" nocase
        $domain62 = "denux.nl" nocase
        $domain63 = "derksenadvocatuur.nl" nocase
        $domain64 = "detectis.ru" nocase
        $domain65 = "dev-techniek.nl" nocase
        $domain66 = "deverstandigeraadgever.nl" nocase
        $domain67 = "digitalbulls.nl" nocase
        $domain68 = "digitalplanit.nl" nocase
        $domain69 = "doacare.nl" nocase
        $domain70 = "doacarethuiszorg.nl" nocase
        $domain71 = "donbosco-wijnegem.be" nocase
        $domain72 = "dooperprojects.nl" nocase
        $domain73 = "dorpsplatformlinschoten.nl" nocase
        $domain74 = "downdown.ru" nocase
        $domain75 = "dragonfires.ru" nocase
        $domain76 = "drunken-bumble.be" nocase
        $domain77 = "drzabaleta.com" nocase
        $domain78 = "dv-personenvervoer.be" nocase
        $domain79 = "eclipsettt.eu" nocase
        $domain80 = "ecoshelter.be" nocase
        $domain81 = "edses.com" nocase
        $domain82 = "eetsmakelijketulp.nl" nocase
        $domain83 = "email-informer.ru" nocase
        $domain84 = "email-office.ru" nocase
        $domain85 = "email-rembler.ru" nocase
        $domain86 = "emailoff.ru" nocase
        $domain87 = "emailoffice.ru" nocase
        $domain88 = "emailon.ru" nocase
        $domain89 = "empiremuziek.nl" nocase
        $domain90 = "etnicom.nl" nocase
        $domain91 = "exz-warehousing.nl" nocase
        $domain92 = "fgub-vniir.ph" nocase
        $domain93 = "fgub-vniir.space" nocase
        $domain94 = "fidelfloris.eu" nocase
        $domain95 = "fidelfloris.nl" nocase
        $domain96 = "flytechaviationgroup.com" nocase
        $domain97 = "forukrainians.eu" nocase
        $domain98 = "frontend.fr.po21.net" nocase
        $domain99 = "ftfinancial.nl" nocase
        $ip100 = "92.63.173.61"

    condition:
        any of them
}

rule APT_LONGHORN {
    meta:
        description = "Indicators associated with APT LONGHORN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-39, lambert, coloredlamberts"

    strings:
        $domain0 = "cdn.fmlstatic.com" nocase
        $domain1 = "financasdebrasil.com" nocase
        $domain2 = "fmlstatic.com" nocase
        $domain3 = "uaefinance.org" nocase
        $ip4 = "103.242.119.71"
        $ip5 = "120.50.38.187"
        $ip6 = "161.5.6.206"

    condition:
        any of them
}

rule APT_LONGNOSEDGOBLIN {
    meta:
        description = "Indicators associated with APT LONGNOSEDGOBLIN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "nosydownloader, nosydoor, nosyhistorian"

    strings:
        $domain0 = "assesscompplan.com" nocase
        $domain1 = "blazenewso.com" nocase
        $domain2 = "privacypolicy-my.com" nocase
        $domain3 = "rethinkpayequity.com" nocase
        $domain4 = "sslvpnserver.com" nocase
        $domain5 = "threadstub.com" nocase

    condition:
        any of them
}

rule APT_LOTUSBLOSSOM {
    meta:
        description = "Indicators associated with APT LOTUSBLOSSOM"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "chrysalis, warbird, hacked notepad++"

    strings:
        $domain0 = "38qmk6.0to9.info" nocase
        $domain1 = "3qyo4o7.7r7i3.info" nocase
        $domain2 = "7g91xhp.envuy3.net" nocase
        $domain3 = "aliancesky.com" nocase
        $domain4 = "api.cloudtrafficservice.com" nocase
        $domain5 = "api.skycloudcenter.com" nocase
        $domain6 = "api.wiresguard.com" nocase
        $domain7 = "asean-star.com" nocase
        $domain8 = "aseaneco.org" nocase
        $domain9 = "aseansec.dynalias.org" nocase
        $domain10 = "babysoal.com" nocase
        $domain11 = "beckhammer.xicp.net" nocase
        $domain12 = "boshman09.com" nocase
        $domain13 = "cdncheck.it.com" nocase
        $domain14 = "chris201.net" nocase
        $domain15 = "cloudtrafficservice.com" nocase
        $domain16 = "cpcl2006.dyndns-free.com" nocase
        $domain17 = "cybertunnel.dyndns.info" nocase
        $domain18 = "dtdf5vu.nt7yq.info" nocase
        $domain19 = "harryleed.dyndns.org" nocase
        $domain20 = "iascas.net" nocase
        $domain21 = "imonju.com" nocase
        $domain22 = "imonju.net" nocase
        $domain23 = "interhero.net" nocase
        $domain24 = "j.4tc3ldw.g9ml.www0.org" nocase
        $domain25 = "jackyson.dyndns.info" nocase
        $domain26 = "kid.dyndns.org" nocase
        $domain27 = "kjd.dyndns.org" nocase
        $domain28 = "l.hovux.eln9wj7.7gpj.org" nocase
        $domain29 = "newinfo32.eicp.net" nocase
        $domain30 = "newshappys.dyndns-blog.com" nocase
        $domain31 = "petto.mooo.com" nocase
        $domain32 = "phil-army.gotdns.org" nocase
        $domain33 = "phil-gov.gotdns.org" nocase
        $domain34 = "safe-dns.it.com" nocase
        $domain35 = "scristioned.dyndns-web.com" nocase
        $domain36 = "seachers.net" nocase
        $domain37 = "self-dns.it.com" nocase
        $domain38 = "serchers.net" nocase
        $domain39 = "shotacon.dyndns.info" nocase
        $domain40 = "skycloudcenter.com" nocase
        $domain41 = "tgecc.org" nocase
        $domain42 = "tintuchoahau.com" nocase
        $domain43 = "ubkv1t.ec0.com" nocase
        $domain44 = "usa-moon.net" nocase
        $domain45 = "verolalia.dyndns.org" nocase
        $domain46 = "vienclp.com" nocase
        $domain47 = "w.7sytdjc.wroi.cxy.com" nocase
        $domain48 = "wiresguard.com" nocase
        $domain49 = "wsi.dyndns.org" nocase
        $domain50 = "www3.bkav2010.net" nocase
        $ip51 = "124.222.137.114"
        $ip52 = "59.110.7.32"
        $ip53 = "59.110.7.32"
        $ip54 = "95.179.213.0"
        $ip55 = "95.179.213.0"

    condition:
        any of them
}

rule APT_LUCKYCAT {
    meta:
        description = "Indicators associated with APT LUCKYCAT"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "sepulcher, ta413, exilerat"

    strings:
        $domain0 = "89757.x.gg" nocase
        $domain1 = "airjaldi.online" nocase
        $domain2 = "applestatic.com" nocase
        $domain3 = "bailianlan.c.dwyu.com" nocase
        $domain4 = "cattree.1x.biz" nocase
        $domain5 = "charlesbrain.shop.co" nocase
        $domain6 = "clbest.greenglassint.net" nocase
        $domain7 = "dalailamatrustindia.ddns.net" nocase
        $domain8 = "duojee.info" nocase
        $domain9 = "fidk.rkntils.dnset.com" nocase
        $domain10 = "fireequipment.website.org" nocase
        $domain11 = "flex-jobs.in" nocase
        $domain12 = "footballworldcup.website.org" nocase
        $domain13 = "frankwhales.shop.co" nocase
        $domain14 = "freetibet.in" nocase
        $domain15 = "gmailcom.tw" nocase
        $domain16 = "goodwell.all.co.uk" nocase
        $domain17 = "havefuns.rkntils.10dig.net" nocase
        $domain18 = "hi21222325.x.gg" nocase
        $domain19 = "indiatrustdalailama.com" nocase
        $domain20 = "jeepvihecle.shop.co" nocase
        $domain21 = "jobflex.in" nocase
        $domain22 = "johnnees.rkntils.10dig.net" nocase
        $domain23 = "killmannets.0fees.net" nocase
        $domain24 = "kinkeechow.shop.co" nocase
        $domain25 = "kittyshop.kilu.org" nocase
        $domain26 = "lucysmith.0fees.net" nocase
        $domain27 = "maritimemaster.kilu.org" nocase
        $domain28 = "masterchoice.shop.co" nocase
        $domain29 = "mondaynews.tk" nocase
        $domain30 = "nangsihistory.vip" nocase
        $domain31 = "newsindian.xyz" nocase
        $domain32 = "peopleoffreeworld.tk" nocase
        $domain33 = "perfect.shop.co" nocase
        $domain34 = "pumasports.website.org" nocase
        $domain35 = "rediffpapers.com" nocase
        $domain36 = "rkntils.10dig.net" nocase
        $domain37 = "rkntils.dnset.com" nocase
        $domain38 = "rukiyeangel.dyndns.pro" nocase
        $domain39 = "sunshine.shop.co" nocase
        $domain40 = "tb123.xoomsite.com" nocase
        $domain41 = "tbda123.gwchost.com" nocase
        $domain42 = "tennissport.website.org" nocase
        $domain43 = "tibet-gov.web.app" nocase
        $domain44 = "tibet.bet" nocase
        $domain45 = "tibetancongress.com" nocase
        $domain46 = "tibetanyouthcongress.com" nocase
        $domain47 = "toms.0fees.net" nocase
        $domain48 = "tomsburs.shop.co" nocase
        $domain49 = "tomygreen.0fees.net" nocase
        $domain50 = "vaccine-icmr.net" nocase
        $domain51 = "vaccine-icmr.org" nocase
        $domain52 = "vpoasport.shopping2000.com" nocase
        $domain53 = "waterpool.website.org" nocase
        $domain54 = "welfaretibet.tk" nocase
        $domain55 = "you-tube.tv" nocase
        $ip56 = "107.151.194.197"
        $ip57 = "107.151.194.197"
        $ip58 = "118.99.13.4"
        $ip59 = "118.99.13.4"
        $ip60 = "167.179.99.136"
        $ip61 = "27.126.188.212"
        $ip62 = "27.126.188.212"
        $ip63 = "27.126.188.212"

    condition:
        any of them
}

rule APT_LUMINOUSMOTH {
    meta:
        description = "Indicators associated with APT LUMINOUSMOTH"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "7daydai1y.com" nocase
        $domain1 = "irrawddy.com" nocase
        $domain2 = "mmtimes.net" nocase
        $domain3 = "mmtimes.org" nocase
        $domain4 = "mopfi-ferd.com" nocase
        $domain5 = "updatecatalogs.com" nocase
        $domain6 = "webmail.mmtimes.net" nocase

    condition:
        any of them
}

rule APT_LYCEUM {
    meta:
        description = "Indicators associated with APT LYCEUM"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "danbot, hexane, lyceum"

    strings:
        $domain0 = "akastatus.com" nocase
        $domain1 = "bsolutions-cloude.com" nocase
        $domain2 = "centosupdatecdn.com" nocase
        $domain3 = "cloudmsn.net" nocase
        $domain4 = "cyberclub.one" nocase
        $domain5 = "cybersecnet.co.za" nocase
        $domain6 = "cybersecnet.org" nocase
        $domain7 = "defenderlive.com" nocase
        $domain8 = "defenderstatus.com" nocase
        $domain9 = "digitalmarketingnews.net" nocase
        $domain10 = "dmgagency.net" nocase
        $domain11 = "dnscachecloud.com" nocase
        $domain12 = "dnscatalog.net" nocase
        $domain13 = "dnscdn.org" nocase
        $domain14 = "dnscloudservice.com" nocase
        $domain15 = "dnsstatus.org" nocase
        $domain16 = "excsrvcdn.com" nocase
        $domain17 = "he-express-marketing.com" nocase
        $domain18 = "hpesystem.com" nocase
        $domain19 = "jobschippc.com" nocase
        $domain20 = "livecdn.com" nocase
        $domain21 = "main.download" nocase
        $domain22 = "mastertape.org" nocase
        $domain23 = "microsftonline.net" nocase
        $domain24 = "msnnews.org" nocase
        $domain25 = "news-reporter.xyz" nocase
        $domain26 = "news-spot.live" nocase
        $domain27 = "news-spot.xyz" nocase
        $domain28 = "online-analytic.com" nocase
        $domain29 = "onlineoutlook.net" nocase
        $domain30 = "opendnscloud.com" nocase
        $domain31 = "planet-informer.me" nocase
        $domain32 = "science-news.live" nocase
        $domain33 = "securednsservice.net" nocase
        $domain34 = "softwareagjobs.com" nocase
        $domain35 = "stgeorgebankers.com" nocase
        $domain36 = "sysadminnews.info" nocase
        $domain37 = "uctpostgraduate.com" nocase
        $domain38 = "updatecdn.net" nocase
        $domain39 = "web-statistics.info" nocase
        $domain40 = "web-traffic.info" nocase
        $domain41 = "webmaster-team.com" nocase
        $domain42 = "windowsupdatecdn.com" nocase
        $domain43 = "wsuslink.com" nocase
        $domain44 = "zonestatistic.com" nocase
        $ip45 = "104.249.26.60"
        $ip46 = "185.243.112.136"
        $ip47 = "185.243.112.136"
        $ip48 = "85.206.175.199"
        $ip49 = "89.39.149.18"
        $ip50 = "89.39.149.18"
        $ip51 = "89.39.149.18"

    condition:
        any of them
}

rule APT_MACHETE {
    meta:
        description = "Indicators associated with APT MACHETE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt43, apt-c-43"

    strings:
        $domain0 = "6e24a5fb.ngrok.io" nocase
        $domain1 = "adtiomtardecessd.zapto.org" nocase
        $domain2 = "agaliarept.com" nocase
        $domain3 = "artyomt.com" nocase
        $domain4 = "asymmetricfile.blogspot.com" nocase
        $domain5 = "blogwhereyou.com" nocase
        $domain6 = "ceofanb18.mipropia.com" nocase
        $domain7 = "correomindefensagobvemyspace.com" nocase
        $domain8 = "djcaps.gotdns.ch" nocase
        $domain9 = "f9527d03.ngrok.io" nocase
        $domain10 = "frejabe.com" nocase
        $domain11 = "funkytothemoon.live" nocase
        $domain12 = "grannegral.com" nocase
        $domain13 = "great-jepsen.51-79-62-98.plesk.page" nocase
        $domain14 = "intelligent-archimedes.51-79-62-98.plesk.page" nocase
        $domain15 = "java.serveblog.net" nocase
        $domain16 = "koliast.com" nocase
        $domain17 = "lawyersofficial.mipropia.com" nocase
        $domain18 = "mcsi.gotdns.ch" nocase
        $domain19 = "op-icaro.site" nocase
        $domain20 = "plushbr.com" nocase
        $domain21 = "pompst.store" nocase
        $domain22 = "postinfomatico.blogspot.com" nocase
        $domain23 = "pumapomp.store" nocase
        $domain24 = "sangeet1.000webhostapp.com" nocase
        $domain25 = "skyscopeups.cfd" nocase
        $domain26 = "soldatenkovarten.com" nocase
        $domain27 = "solutionconect.online" nocase
        $domain28 = "surgutneftegazappstore.com" nocase
        $domain29 = "tobabean.expert" nocase
        $domain30 = "tokeiss.ddns.net" nocase
        $domain31 = "u154611594.hostingerapp.com" nocase
        $domain32 = "u929489355.hostingerapp.com" nocase
        $domain33 = "xmailliwx.com" nocase
        $ip34 = "31.207.44.72"
        $ip35 = "31.207.45.243"

    condition:
        any of them
}

rule APT_MALKAMAK {
    meta:
        description = "Indicators associated with APT MALKAMAK"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "azure.ms-tech.us" nocase
        $domain1 = "ms-tech.us" nocase
        $domain2 = "whynooneistherefornoneofthem.com" nocase

    condition:
        any of them
}

rule APT_MARBLEDDUST {
    meta:
        description = "Indicators associated with APT MARBLEDDUST"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "api.wordinfos.com" nocase
        $domain1 = "wordinfos.com" nocase

    condition:
        any of them
}

rule APT_MENUPASS {
    meta:
        description = "Indicators associated with APT MENUPASS"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt10, stone panda, gallium"

    strings:
        $domain0 = "002562066559681.r3u8.com" nocase
        $domain1 = "031168053846049.r3u8.com" nocase
        $domain2 = "0625.have8000.com" nocase
        $domain3 = "1.gadskysun.com" nocase
        $domain4 = "100fanwen.com" nocase
        $domain5 = "11.usyahooapis.com" nocase
        $domain6 = "19518473326.r3u8.com" nocase
        $domain7 = "1960445709311199.r3u8.com" nocase
        $domain8 = "1j.www1.biz" nocase
        $domain9 = "1z.itsaol.com" nocase
        $domain10 = "2012yearleft.com" nocase
        $domain11 = "2014.zzux.com" nocase
        $domain12 = "202017845.r3u8.com" nocase
        $domain13 = "2139465544784.r3u8.com" nocase
        $domain14 = "2789203959848958.r3u8.com" nocase
        $domain15 = "5590428449750026.r3u8.com" nocase
        $domain16 = "5q.niushenghuo.info" nocase
        $domain17 = "6r.suibian2010.info" nocase
        $domain18 = "9gowg.tech" nocase
        $domain19 = "Jepsen.r3u8.com" nocase
        $domain20 = "a.wubangtu.info" nocase
        $domain21 = "a1.suibian2010.info" nocase
        $domain22 = "ab.4pu.com" nocase
        $domain23 = "abc.wikaba.com" nocase
        $domain24 = "abcd100621.3322.org" nocase
        $domain25 = "abcd120719.6600.org" nocase
        $domain26 = "abcd120807.3322.org" nocase
        $domain27 = "acc.emailfound.info" nocase
        $domain28 = "acc.lehigtapp.com" nocase
        $domain29 = "acsocietyy.com" nocase
        $domain30 = "ad.getfond.info" nocase
        $domain31 = "ad.webbooting.com" nocase
        $domain32 = "additional.sexidude.com" nocase
        $domain33 = "af.zyns.com" nocase
        $domain34 = "afc.https443.org" nocase
        $domain35 = "ako.ddns.us" nocase
        $domain36 = "algorithm.ddnsgeek.com" nocase
        $domain37 = "amsidgoo.thedomais.info" nocase
        $domain38 = "androidmusicapp.onmypc.us" nocase
        $domain39 = "announcements.toythieves.com" nocase
        $domain40 = "anvprn.com" nocase
        $domain41 = "aotuo.9966.org" nocase
        $domain42 = "apec.qtsofta.com" nocase
        $domain43 = "app.lehigtapp.com" nocase
        $domain44 = "apple.cmdnetview.com" nocase
        $domain45 = "apple.defensewar.org" nocase
        $domain46 = "apple.ikwb.com" nocase
        $domain47 = "appledownload.ourhobby.com" nocase
        $domain48 = "appleimages.itemdb.com" nocase
        $domain49 = "appleimages.longmusic.com" nocase
        $domain50 = "applelib120102.9966.org" nocase
        $domain51 = "applemirror.organiccrap.com" nocase
        $domain52 = "applemirror.squirly.info" nocase
        $domain53 = "applemusic.isasecret.com" nocase
        $domain54 = "applemusic.itemdb.com" nocase
        $domain55 = "applemusic.wikaba.com" nocase
        $domain56 = "applemusic.xxuz.com" nocase
        $domain57 = "applemusic.zzux.com" nocase
        $domain58 = "apples.sytes.net" nocase
        $domain59 = "appleupdate.itemdb.com" nocase
        $domain60 = "architectisusa.com" nocase
        $domain61 = "area.wthelpdesk.com" nocase
        $domain62 = "arkouowi.com" nocase
        $domain63 = "army.xxuz.com" nocase
        $domain64 = "art.p6p6.net" nocase
        $domain65 = "asfzx.x24hr.com" nocase
        $domain66 = "asyspy256.ddns.net" nocase
        $domain67 = "av.ddns.us" nocase
        $domain68 = "availab.wikaba.com" nocase
        $domain69 = "availability.justdied.com" nocase
        $domain70 = "ba.my03.com" nocase
        $domain71 = "baby.macforlinux.net" nocase
        $domain72 = "baby.myie12.com" nocase
        $domain73 = "baby.usmirocomney.net" nocase
        $domain74 = "babyprintf.2288.org" nocase
        $domain75 = "back.jungleheart.com" nocase
        $domain76 = "back.mofa.dynamic-dns.net" nocase
        $domain77 = "bak.have8000.com" nocase
        $domain78 = "bak.ignorelist.com" nocase
        $domain79 = "bak.un.dnsrd.com" nocase
        $domain80 = "balance1.wikaba.com" nocase
        $domain81 = "balk.n7go.com" nocase
        $domain82 = "banana.cmdnetview.com" nocase
        $domain83 = "barrybaker.6600.org" nocase
        $domain84 = "bbs.jungleheart.com" nocase
        $domain85 = "bdoncloud.com" nocase
        $domain86 = "be.mrslove.com" nocase
        $domain87 = "be.yourtrap.com" nocase
        $domain88 = "belowto.com" nocase
        $domain89 = "bethel.webhop.net" nocase
        $domain90 = "bexm.cleansite.biz" nocase
        $domain91 = "bezu.itemdb.com" nocase
        $domain92 = "bk56.twilightparadox.com" nocase
        $domain93 = "blaaaaaaaaaaaa.windowsupdate.3-a.net" nocase
        $domain94 = "blog.defensewar.org" nocase
        $domain95 = "brand.fartit.com" nocase
        $domain96 = "bridgeluxlightmadness.com" nocase
        $domain97 = "bulk.tmpxctl.com" nocase
        $domain98 = "bulletproof.squirly.info" nocase
        $domain99 = "caibi379.com" nocase
        $ip100 = "185.117.88.80"
        $ip101 = "204.79.197.200"
        $ip102 = "31.220.92.125"
        $ip103 = "45.76.222.130"
        $ip104 = "45.77.183.161"
        $ip105 = "5.181.25.99"
        $ip106 = "61.221.66.85"
        $ip107 = "89.117.79.31"
        $ip108 = "89.117.79.31"
        $ip109 = "89.117.79.31"
        $ip110 = "89.117.79.31"

    condition:
        any of them
}

rule APT_MERCENARYAMANDA {
    meta:
        description = "Indicators associated with APT MERCENARYAMANDA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "Dark Basin"

    strings:
        $domain0 = "2mblk.com" nocase
        $domain1 = "4mblk.com" nocase
        $domain2 = "ablyazovangels.com" nocase
        $domain3 = "ablyazovcog.com" nocase
        $domain4 = "ablyazovcrimestory.com" nocase
        $domain5 = "ablyazovcrimesyndicate.com" nocase
        $domain6 = "ablyazovcriminalgang.com" nocase
        $domain7 = "ablyazovcriminals.com" nocase
        $domain8 = "ablyazovgang.com" nocase
        $domain9 = "ablyazovmafia.com" nocase
        $domain10 = "ablyazovorganisedcrime.com" nocase
        $domain11 = "affiliatedomainservice.com" nocase
        $domain12 = "affliatedomainservice.com" nocase
        $domain13 = "allaboutiot.website" nocase
        $domain14 = "anitmationworldnews.com" nocase
        $domain15 = "anothershortnr.com" nocase
        $domain16 = "aplsrvrer.com" nocase
        $domain17 = "assuredreturnplan.com" nocase
        $domain18 = "auditionregistrationonline.com" nocase
        $domain19 = "backwaterreservoir.com" nocase
        $domain20 = "basemailservice.com" nocase
        $domain21 = "baseserveremailbg.com" nocase
        $domain22 = "basichostingrussia.com" nocase
        $domain23 = "basichostnetservice.com" nocase
        $domain24 = "basicmyoffshore.com" nocase
        $domain25 = "basicruoffshore.com" nocase
        $domain26 = "basicservicehk.com" nocase
        $domain27 = "basicservicelux.com" nocase
        $domain28 = "basicservicemy.com" nocase
        $domain29 = "basicservicerus.com" nocase
        $domain30 = "basicservicesg.com" nocase
        $domain31 = "basicsgoffshore.com" nocase
        $domain32 = "bellsouthnetwork.com" nocase
        $domain33 = "belowmargins.com" nocase
        $domain34 = "bitserverhk.com" nocase
        $domain35 = "bitserverlux.com" nocase
        $domain36 = "blogforpranks.com" nocase
        $domain37 = "blogserverlx.com" nocase
        $domain38 = "browserdirectservice.com" nocase
        $domain39 = "browserextensions.info" nocase
        $domain40 = "browserredirect.com" nocase
        $domain41 = "bsrvrer.com" nocase
        $domain42 = "budgtoffmy.com" nocase
        $domain43 = "budgtoffru.com" nocase
        $domain44 = "buzzoffbul.com" nocase
        $domain45 = "buzzoffhk.com" nocase
        $domain46 = "buzzoffmy.com" nocase
        $domain47 = "buzzoffru.com" nocase
        $domain48 = "buzzoffsg.com" nocase
        $domain49 = "capitalinvestmentsllp.com" nocase
        $domain50 = "cathostingservice.com" nocase
        $domain51 = "chatserverrussia.com" nocase
        $domain52 = "checkmailserverhk.com" nocase
        $domain53 = "chromeperfection.com" nocase
        $domain54 = "com-ar-en-us.com" nocase
        $domain55 = "com-authmail.com" nocase
        $domain56 = "com-biz.website" nocase
        $domain57 = "com-com-us.com" nocase
        $domain58 = "com-com.website" nocase
        $domain59 = "com-en-us.co.uk" nocase
        $domain60 = "com-er-en-us.com" nocase
        $domain61 = "com-hl-en-us.com" nocase
        $domain62 = "com-io-en-us.com" nocase
        $domain63 = "com-mail-us.com" nocase
        $domain64 = "com-mail.net" nocase
        $domain65 = "com-nh-en-us.com" nocase
        $domain66 = "com-oa-en-us.com" nocase
        $domain67 = "com-us-en-us.com" nocase
        $domain68 = "com-website33.biz" nocase
        $domain69 = "com-website33.com" nocase
        $domain70 = "com-website33.info" nocase
        $domain71 = "com-website33.net" nocase
        $domain72 = "com-website33.org" nocase
        $domain73 = "comservicelogin.com" nocase
        $domain74 = "corn-en-gb.com" nocase
        $domain75 = "corn-en-us.com" nocase
        $domain76 = "corn-fr-fr.com" nocase
        $domain77 = "corn-lang-eng.com" nocase
        $domain78 = "corn-loginservicesverified.com" nocase
        $domain79 = "corn-msrvrgr.com" nocase
        $domain80 = "corn-servicelogin.com" nocase
        $domain81 = "corn-ukr.com" nocase
        $domain82 = "csrvrer.com" nocase
        $domain83 = "cyberanalyticals.com" nocase
        $domain84 = "cyberserverusa.com" nocase
        $domain85 = "deferrer.website" nocase
        $domain86 = "demoprojectsuk.com" nocase
        $domain87 = "dnsserverprv.com" nocase
        $domain88 = "domainblacklistcheck.com" nocase
        $domain89 = "domainemailhostings.com" nocase
        $domain90 = "domainexpertswebuk.com" nocase
        $domain91 = "domainforhostuk.com" nocase
        $domain92 = "domainformailinguk.com" nocase
        $domain93 = "domainhostnetworkuk.com" nocase
        $domain94 = "domainhostnetworkusa.com" nocase
        $domain95 = "domainhostworkeu.com" nocase
        $domain96 = "domainlocalhostingeu.com" nocase
        $domain97 = "domainlocalhostinghk.com" nocase
        $domain98 = "domainlocalhostinguk.com" nocase
        $domain99 = "domainmanager33.com" nocase

    condition:
        any of them
}

rule APT_MIDDLEEAST {
    meta:
        description = "Indicators associated with APT MIDDLEEAST"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "1e100.tech" nocase
        $domain1 = "1m100.tech" nocase
        $domain2 = "ads-youtube.net" nocase
        $domain3 = "ads-youtube.online" nocase
        $domain4 = "ads-youtube.tech" nocase
        $domain5 = "akamai.press" nocase
        $domain6 = "akamaitechnology.com" nocase
        $domain7 = "akamaitechnology.tech" nocase
        $domain8 = "alkamaihd.com" nocase
        $domain9 = "alkamaihd.net" nocase
        $domain10 = "azurewebsites.tech" nocase
        $domain11 = "big-windowss.com" nocase
        $domain12 = "britishnews.press" nocase
        $domain13 = "broadcast-microsoft.tech" nocase
        $domain14 = "cachevideo.com" nocase
        $domain15 = "cachevideo.online" nocase
        $domain16 = "cachevideo.xyz" nocase
        $domain17 = "chromeupdates.online" nocase
        $domain18 = "chromium.online" nocase
        $domain19 = "cissco.net" nocase
        $domain20 = "clalit.press" nocase
        $domain21 = "cloud-analyzer.com" nocase
        $domain22 = "cloudflare-analyse.com" nocase
        $domain23 = "cloudflare-analyse.xyz" nocase
        $domain24 = "cloudflare-statics.com" nocase
        $domain25 = "cloudflare.news" nocase
        $domain26 = "cloudflare.site" nocase
        $domain27 = "cloudmicrosoft.net" nocase
        $domain28 = "cortana-search.com" nocase
        $domain29 = "digicert.online" nocase
        $domain30 = "digicert.space" nocase
        $domain31 = "digicert.xyz" nocase
        $domain32 = "dnsserv.host" nocase
        $domain33 = "elasticbeanstalk.tech" nocase
        $domain34 = "f-tqn.com" nocase
        $domain35 = "fb-nameserver.com" nocase
        $domain36 = "fb-statics.com" nocase
        $domain37 = "fb-statics.info" nocase
        $domain38 = "fbcdn.bid" nocase
        $domain39 = "fbexternal-a.press" nocase
        $domain40 = "fbexternal-a.pw" nocase
        $domain41 = "fbstatic-a.space" nocase
        $domain42 = "fbstatic-a.xyz" nocase
        $domain43 = "fbstatic-akamaihd.com" nocase
        $domain44 = "fdgdsg.xyz" nocase
        $domain45 = "githubapp.online" nocase
        $domain46 = "githubapp.tech" nocase
        $domain47 = "githubusecontent.tech" nocase
        $domain48 = "gmailtagmanager.com" nocase
        $domain49 = "google-api-analyse.com" nocase
        $domain50 = "google-api-update.com" nocase
        $domain51 = "hamedia.xyz" nocase
        $domain52 = "hotseller.info" nocase
        $domain53 = "intel-api.com" nocase
        $domain54 = "intelchip.org" nocase
        $domain55 = "ipresolver.org" nocase
        $domain56 = "javaupdator.com" nocase
        $domain57 = "jguery.net" nocase
        $domain58 = "jguery.online" nocase
        $domain59 = "kernel4windows.in" nocase
        $domain60 = "labs-cloudfront.com" nocase
        $domain61 = "mcafee-analyzer.com" nocase
        $domain62 = "mcafee-monitoring.com" nocase
        $domain63 = "mcafeemonitoring.com" nocase
        $domain64 = "micro-windows.in" nocase
        $domain65 = "microsoft-ds.com" nocase
        $domain66 = "microsoft-security.host" nocase
        $domain67 = "microsoft-tool.com" nocase
        $domain68 = "microsoftserver.org" nocase
        $domain69 = "mpmicrosoft.com" nocase
        $domain70 = "mssqlupdate.com" nocase
        $domain71 = "mswordupdate15.com" nocase
        $domain72 = "mswordupdate16.com" nocase
        $domain73 = "mswordupdate17.com" nocase
        $domain74 = "myservers.site" nocase
        $domain75 = "mywindows24.in" nocase
        $domain76 = "nameserver.win" nocase
        $domain77 = "nasr.xyz" nocase
        $domain78 = "newsfeeds-microsoft.press" nocase
        $domain79 = "nsserver.host" nocase
        $domain80 = "officeapps-live.com" nocase
        $domain81 = "officeapps-live.net" nocase
        $domain82 = "officeapps-live.org" nocase
        $domain83 = "onlinewebcam.press" nocase
        $domain84 = "outlook360.net" nocase
        $domain85 = "outlook360.org" nocase
        $domain86 = "owa-microsoft.online" nocase
        $domain87 = "patch7-windows.com" nocase
        $domain88 = "patch8-windows.com" nocase
        $domain89 = "patchthiswindows.com" nocase
        $domain90 = "qoldenlines.net" nocase
        $domain91 = "sdlc-esd-oracle.online" nocase
        $domain92 = "sharepoint-microsoft.co" nocase
        $domain93 = "sphotos-b.bid" nocase
        $domain94 = "sphotos-b.pw" nocase
        $domain95 = "ssl-gstatic.net" nocase
        $domain96 = "ssl-gstatic.online" nocase
        $domain97 = "static.news" nocase
        $domain98 = "symcd.site" nocase
        $domain99 = "symcd.xyz" nocase

    condition:
        any of them
}

rule APT_MIDDLEFLOOR {
    meta:
        description = "Indicators associated with APT MIDDLEFLOOR"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-unk2"

    strings:
        $domain0 = "cert-pl.pl" nocase
        $domain1 = "comunicacion-presidencia-gov.es" nocase
        $domain2 = "comunidad-madrid.es" nocase
        $domain3 = "energie-gov.md" nocase
        $domain4 = "eupm-moldova.md" nocase
        $domain5 = "europa-ec.eu" nocase
        $domain6 = "europa-eppo.eu" nocase
        $domain7 = "europa.social" nocase
        $domain8 = "europa.study" nocase
        $domain9 = "freepresunlimited.org" nocase
        $domain10 = "golebewski.pl" nocase
        $domain11 = "gov-md.com" nocase
        $domain12 = "interior-gov.es" nocase
        $domain13 = "isw-org.pl" nocase
        $domain14 = "ivention.pl" nocase
        $domain15 = "litexpo-portal.lt" nocase
        $domain16 = "mailgon.online" nocase
        $domain17 = "mailorun.su" nocase
        $domain18 = "mailos.ru" nocase
        $domain19 = "mc-md.com" nocase
        $domain20 = "mcgov.md" nocase
        $domain21 = "md-mec.com" nocase
        $domain22 = "mec-gov.md" nocase
        $domain23 = "moldova-energie.md" nocase
        $domain24 = "moldova-mediu.md" nocase
        $domain25 = "moldova-social.md" nocase
        $domain26 = "nask-pl.com" nocase
        $domain27 = "nnmnnm.ru" nocase
        $domain28 = "noname05716.ru" nocase
        $domain29 = "otllook.com" nocase
        $domain30 = "pass-check.online" nocase
        $domain31 = "sapsap.site" nocase
        $domain32 = "social-moldova.md" nocase
        $domain33 = "socialisti.md" nocase
        $domain34 = "socialistii.com" nocase
        $domain35 = "sso-log.com" nocase
        $domain36 = "te-storg.com" nocase
        $domain37 = "urm-lt.com" nocase
        $domain38 = "viilnius.lt" nocase
        $domain39 = "vilnius-summit.lt" nocase

    condition:
        any of them
}

rule APT_MINIDUKE {
    meta:
        description = "Indicators associated with APT MINIDUKE"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "arabooks.ch" nocase
        $domain1 = "artas.org" nocase
        $domain2 = "eamtm.com" nocase
        $domain3 = "extremesportsevents.net" nocase
        $domain4 = "news.grouptumbler.com" nocase
        $domain5 = "tsoftonline.com" nocase

    condition:
        any of them
}

rule APT_MIRRORFACE {
    meta:
        description = "Indicators associated with APT MIRRORFACE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "mirrorstealer, lodeinfo"

    strings:
        $domain0 = "aesorunwe.com" nocase
        $domain1 = "ninesmn.com" nocase
        $ip2 = "104.238.149.37"
        $ip3 = "108.160.138.20"
        $ip4 = "139.180.197.13"
        $ip5 = "149.28.31.17"
        $ip6 = "167.179.105.29"
        $ip7 = "198.13.51.211"
        $ip8 = "198.13.55.8"
        $ip9 = "207.148.104.176"
        $ip10 = "43.224.34.61"
        $ip11 = "45.32.14.107"
        $ip12 = "45.32.18.42"
        $ip13 = "45.76.193.104"
        $ip14 = "45.76.202.254"
        $ip15 = "45.76.202.98"
        $ip16 = "45.76.97.113"
        $ip17 = "45.77.28.195"
        $ip18 = "45.77.29.108"

    condition:
        any of them
}

rule APT_MODIFIEDELEPHANT {
    meta:
        description = "Indicators associated with APT MODIFIEDELEPHANT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "atlaswebportal.zapto.org" nocase
        $domain1 = "bzone.no-ip.biz" nocase
        $domain2 = "chivalkarstone.com" nocase
        $domain3 = "duniaenewsportal.ddns.net" nocase
        $domain4 = "gayakwaad.com" nocase
        $domain5 = "greenpeacesite.com" nocase
        $domain6 = "jasonhistoryarticles.read-books.org" nocase
        $domain7 = "johnmarcus.zapto.org" nocase
        $domain8 = "knudandersen.zapto.org" nocase
        $domain9 = "nepal3.msntv.org" nocase
        $domain10 = "new-agency.us" nocase
        $domain11 = "newmms.ru" nocase
        $domain12 = "pahiclisting.ddns.net" nocase
        $domain13 = "ramesh212121.zapto.org" nocase
        $domain14 = "researchplanet.zapto.org" nocase
        $domain15 = "socialstatistics.zapto.org" nocase
        $domain16 = "socialstudies.zapto.org" nocase
        $domain17 = "testingnew.no-ip.org" nocase
        $domain18 = "vinaychutiya.no-ip.biz" nocase
        $ip19 = "146.148.42.217"
        $ip20 = "222.212.28.30"

    condition:
        any of them
}

rule APT_MOTORBEACON {
    meta:
        description = "Indicators associated with APT MOTORBEACON"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "CAPI backdoor"

    strings:
        $domain0 = "carprlce.ru" nocase
        $ip1 = "91.223.75.96"
        $ip2 = "91.223.75.96"

    condition:
        any of them
}

rule APT_MOUSTACHEDBOUNCER {
    meta:
        description = "Indicators associated with APT MOUSTACHEDBOUNCER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "centrocspupdate.com" nocase
        $domain1 = "dervasopssec.com" nocase
        $domain2 = "edgeupdate-security-windows.com" nocase
        $domain3 = "ocsp-atomsecure.com" nocase
        $domain4 = "securityocspdev.com" nocase
        $ip5 = "209.19.37.184"
        $ip6 = "24.9.51.94"
        $ip7 = "35.214.56.2"
        $ip8 = "38.9.8.78"
        $ip9 = "52.3.8.25"
        $ip10 = "59.6.8.25"

    condition:
        any of them
}

rule APT_MUDCARP {
    meta:
        description = "Indicators associated with APT MUDCARP"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt40, apt-c-40, leviathan"

    strings:
        $domain0 = "accountsx.bounceme.net" nocase
        $domain1 = "api.dreamsbottle.com" nocase
        $domain2 = "appexistence.com" nocase
        $domain3 = "armybar.hopto.org" nocase
        $domain4 = "australianmorningnews.com" nocase
        $domain5 = "bbranchs.com" nocase
        $domain6 = "byfleur.myftp.org" nocase
        $domain7 = "cankerscarcass.com" nocase
        $domain8 = "capitana.onthewifi.com" nocase
        $domain9 = "cdn.aexhausts.com" nocase
        $domain10 = "chemscalere.com" nocase
        $domain11 = "cm.musicandfile.com" nocase
        $domain12 = "cnnzapmeta.com" nocase
        $domain13 = "dexercisep.com" nocase
        $domain14 = "duutsxlydw.com" nocase
        $domain15 = "dynamics.ddnsking.com" nocase
        $domain16 = "eujinonline.sytes.net" nocase
        $domain17 = "goo2k88yyh2.chickenkiller.com" nocase
        $domain18 = "guardggg.com" nocase
        $domain19 = "heraldsun.me" nocase
        $domain20 = "iherlvufjknw.com" nocase
        $domain21 = "image.australianmorningnews.com" nocase
        $domain22 = "ja.iherlvufjknw.com" nocase
        $domain23 = "katy197.chickenkiller.com" nocase
        $domain24 = "kulkarni.bounceme.net" nocase
        $domain25 = "laodailylive.com" nocase
        $domain26 = "laodata.network" nocase
        $domain27 = "laodiplomat.com" nocase
        $domain28 = "laotranslations.com" nocase
        $domain29 = "mail2.ignorelist.com" nocase
        $domain30 = "manaloguek.com" nocase
        $domain31 = "microsql-update.info" nocase
        $domain32 = "mihybb.com" nocase
        $domain33 = "mlcdailynews.com" nocase
        $domain34 = "musicandfile.com" nocase
        $domain35 = "networkslaoupdate.com" nocase
        $domain36 = "news.duutsxlydw.com" nocase
        $domain37 = "news.networkslaoupdate.com" nocase
        $domain38 = "nmw4xhipveaca7hm.onion.link" nocase
        $domain39 = "office.duutsxlydw.com" nocase
        $domain40 = "porndec143.chickenkiller.com" nocase
        $domain41 = "regionail.xyz" nocase
        $domain42 = "rninhsss.com" nocase
        $domain43 = "scsnewstoday.com" nocase
        $domain44 = "soure7788.chickenkiller.com" nocase
        $domain45 = "teledynegroup.com" nocase
        $domain46 = "testdomain2019.chickenkiller.com" nocase
        $domain47 = "theaustralian.in" nocase
        $domain48 = "thestar.live" nocase
        $domain49 = "thestar.serveblog.net" nocase
        $domain50 = "thyssenkrupp-marinesystems.org" nocase
        $domain51 = "togetno992.mooo.com" nocase
        $domain52 = "tojenner97.chickenkiller.com" nocase
        $domain53 = "tomema.myddns.me" nocase
        $domain54 = "ttxs.aexhausts.com" nocase
        $domain55 = "vser.mooo.com" nocase
        $domain56 = "vvavesltd.servebeer.com" nocase
        $domain57 = "walmartsde.com" nocase
        $domain58 = "wsmcoff.com" nocase
        $domain59 = "xbug.uk.to" nocase
        $domain60 = "yorkshire-espana-sa.com" nocase

    condition:
        any of them
}

rule APT_MUDDYWATER {
    meta:
        description = "Indicators associated with APT MUDDYWATER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "BoggySerpens, TEMP.Zagros, Static Kitten"

    strings:
        $domain0 = "0179643.xyz" nocase
        $domain1 = "0195327.xyz" nocase
        $domain2 = "0296458.xyz" nocase
        $domain3 = "0359761.xyz" nocase
        $domain4 = "0416928.xyz" nocase
        $domain5 = "0419726.xyz" nocase
        $domain6 = "0427691.xyz" nocase
        $domain7 = "0437285.xyz" nocase
        $domain8 = "0495813.xyz" nocase
        $domain9 = "0518429.xyz" nocase
        $domain10 = "0584962.xyz" nocase
        $domain11 = "0618497.xyz" nocase
        $domain12 = "0679148.xyz" nocase
        $domain13 = "0682149.xyz" nocase
        $domain14 = "0746382.xyz" nocase
        $domain15 = "0746925.xyz" nocase
        $domain16 = "0857314.xyz" nocase
        $domain17 = "0865174.xyz" nocase
        $domain18 = "0946158.xyz" nocase
        $domain19 = "0947682.xyz" nocase
        $domain20 = "0973642.xyz" nocase
        $domain21 = "0973648.xyz" nocase
        $domain22 = "1059748.xyz" nocase
        $domain23 = "108901.xyz" nocase
        $domain24 = "115437.xyz" nocase
        $domain25 = "116240.xyz" nocase
        $domain26 = "118462.xyz" nocase
        $domain27 = "118652.xyz" nocase
        $domain28 = "119012.xyz" nocase
        $domain29 = "120459.xyz" nocase
        $domain30 = "120974.xyz" nocase
        $domain31 = "12498376.xyz" nocase
        $domain32 = "126805.xyz" nocase
        $domain33 = "126841.xyz" nocase
        $domain34 = "1274672.xyz" nocase
        $domain35 = "1279578.xyz" nocase
        $domain36 = "128901.xyz" nocase
        $domain37 = "129012.xyz" nocase
        $domain38 = "1307486.xyz" nocase
        $domain39 = "132345.xyz" nocase
        $domain40 = "132579.xyz" nocase
        $domain41 = "132690.xyz" nocase
        $domain42 = "1327589.xyz" nocase
        $domain43 = "1357806.xyz" nocase
        $domain44 = "1365084.xyz" nocase
        $domain45 = "1368497.xyz" nocase
        $domain46 = "138901.xyz" nocase
        $domain47 = "139012.xyz" nocase
        $domain48 = "143456.xyz" nocase
        $domain49 = "143682.xyz" nocase
        $domain50 = "144567.xyz" nocase
        $domain51 = "1459738.xyz" nocase
        $domain52 = "14638275.xyz" nocase
        $domain53 = "1485390.xyz" nocase
        $domain54 = "148901.xyz" nocase
        $domain55 = "15093472.xyz" nocase
        $domain56 = "1509782.xyz" nocase
        $domain57 = "154567.xyz" nocase
        $domain58 = "1549038.xyz" nocase
        $domain59 = "156738.xyz" nocase
        $domain60 = "1573208.xyz" nocase
        $domain61 = "15820397.xyz" nocase
        $domain62 = "158739.xyz" nocase
        $domain63 = "158901.xyz" nocase
        $domain64 = "159352.xyz" nocase
        $domain65 = "159439.xyz" nocase
        $domain66 = "1597382.xyz" nocase
        $domain67 = "159740.xyz" nocase
        $domain68 = "159842.xyz" nocase
        $domain69 = "160123.xyz" nocase
        $domain70 = "1628394.xyz" nocase
        $domain71 = "163408.xyz" nocase
        $domain72 = "163715.xyz" nocase
        $domain73 = "165438.xyz" nocase
        $domain74 = "1658370.xyz" nocase
        $domain75 = "166504.xyz" nocase
        $domain76 = "166752.xyz" nocase
        $domain77 = "1682957.xyz" nocase
        $domain78 = "168901.xyz" nocase
        $domain79 = "169012.xyz" nocase
        $domain80 = "169327.xyz" nocase
        $domain81 = "169381.xyz" nocase
        $domain82 = "172345.xyz" nocase
        $domain83 = "172839.site" nocase
        $domain84 = "172860.xyz" nocase
        $domain85 = "172946.xyz" nocase
        $domain86 = "173456.xyz" nocase
        $domain87 = "174567.xyz" nocase
        $domain88 = "1746285.xyz" nocase
        $domain89 = "1748906.xyz" nocase
        $domain90 = "1749608.xyz" nocase
        $domain91 = "175130.xyz" nocase
        $domain92 = "175268.xyz" nocase
        $domain93 = "175318.xyz" nocase
        $domain94 = "1754068.xyz" nocase
        $domain95 = "175493.xyz" nocase
        $domain96 = "175678.xyz" nocase
        $domain97 = "1759248.xyz" nocase
        $domain98 = "178026.xyz" nocase
        $domain99 = "178539.xyz" nocase
        $ip100 = "103.27.108.14"
        $ip101 = "103.27.108.14"
        $ip102 = "103.27.109.206"
        $ip103 = "103.27.109.206"
        $ip104 = "103.27.109.52"
        $ip105 = "103.27.109.52"
        $ip106 = "103.43.16.65"
        $ip107 = "103.43.16.65"
        $ip108 = "104.168.44.16"
        $ip109 = "104.194.222.219"
        $ip110 = "104.237.233.38"
        $ip111 = "104.237.233.38"
        $ip112 = "104.237.233.38"
        $ip113 = "104.237.233.40"
        $ip114 = "104.237.233.40"
        $ip115 = "104.237.255.212"
        $ip116 = "107.175.196.104"
        $ip117 = "134.19.215.3"
        $ip118 = "136.243.87.112"
        $ip119 = "137.220.251.44"
        $ip120 = "137.220.251.44"
        $ip121 = "137.74.131.16"
        $ip122 = "141.95.22.153"
        $ip123 = "144.172.111.159"
        $ip124 = "146.19.143.14"
        $ip125 = "146.70.106.89"
        $ip126 = "146.70.124.102"
        $ip127 = "146.70.149.61"
        $ip128 = "149.202.242.80"
        $ip129 = "149.202.242.80"
        $ip130 = "149.202.242.84"
        $ip131 = "149.202.242.85"
        $ip132 = "149.202.242.86"
        $ip133 = "154.90.32.88"
        $ip134 = "157.20.182.49"
        $ip135 = "157.20.182.49"
        $ip136 = "157.20.182.75"
        $ip137 = "157.20.182.75"
        $ip138 = "159.198.36.115"
        $ip139 = "159.198.66.153"
        $ip140 = "159.198.66.153"
        $ip141 = "159.198.66.153"
        $ip142 = "159.198.66.153"
        $ip143 = "159.198.66.153"
        $ip144 = "159.198.66.153"
        $ip145 = "159.198.68.25"
        $ip146 = "159.198.68.25"
        $ip147 = "164.132.237.64"
        $ip148 = "164.132.237.65"
        $ip149 = "164.132.237.66"

    condition:
        any of them
}

rule APT_MURENSHARK {
    meta:
        description = "Indicators associated with APT MURENSHARK"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bookstore.neu.edu.tr" nocase
        $domain1 = "d0g3.cachedns.io" nocase
        $domain2 = "jc.neu.edu.tr" nocase
        $domain3 = "oldies.neu.edu.tr" nocase

    condition:
        any of them
}

rule APT_MUSTANGPANDA {
    meta:
        description = "Indicators associated with APT MUSTANGPANDA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "MQsTTang, RedDelta, Stately Taurus"

    strings:
        $domain0 = "21-ninety.com" nocase
        $domain1 = "247up.org" nocase
        $domain2 = "3012965.securefastserver.com" nocase
        $domain3 = "3784f20bb00.com" nocase
        $domain4 = "9521182.com" nocase
        $domain5 = "aadcdn.msauth.document-invoiceviewer.online" nocase
        $domain6 = "aadcdn.msauth.document-viewer.xyz" nocase
        $domain7 = "aadcdn.msauth.documentpdfviewer.xyz" nocase
        $domain8 = "account.live.document-invoiceviewer.online" nocase
        $domain9 = "account.live.document-viewer.xyz" nocase
        $domain10 = "account.live.office-docs.online" nocase
        $domain11 = "accounts.documentpdfviewer.xyz" nocase
        $domain12 = "accounts.hmailevma5.documentpdfviewer.xyz" nocase
        $domain13 = "adobephotostage.com" nocase
        $domain14 = "ai.nerdnooks.com" nocase
        $domain15 = "aihkstore.com" nocase
        $domain16 = "airdndvn.com" nocase
        $domain17 = "aliyunconsole.com" nocase
        $domain18 = "api.document-invoiceviewer.online" nocase
        $domain19 = "api.document-viewer.xyz" nocase
        $domain20 = "api.office-docs.online" nocase
        $domain21 = "apple-net.com" nocase
        $domain22 = "attd.z23.web.core.windows.net" nocase
        $domain23 = "b.document-viewer.xyz" nocase
        $domain24 = "b83928922.questincc.com" nocase
        $domain25 = "b8pjmgd6.com" nocase
        $domain26 = "babyafrosapparel.com" nocase
        $domain27 = "back.vlvlvlvl.site" nocase
        $domain28 = "backups.muathye.com" nocase
        $domain29 = "bcller.com" nocase
        $domain30 = "blogdirve.com" nocase
        $domain31 = "bonuscave.com" nocase
        $domain32 = "buyonebuy.top" nocase
        $domain33 = "c7p949983.silveradeearyray.com" nocase
        $domain34 = "cabsecnow.com" nocase
        $domain35 = "calendargbmechanical.cam" nocase
        $domain36 = "calendarthomastecs.cam" nocase
        $domain37 = "calendercongress.cam" nocase
        $domain38 = "calendercongress.com" nocase
        $domain39 = "careerhuawei.net" nocase
        $domain40 = "cdn.update.huaweiyuncdn.com" nocase
        $domain41 = "cdn1.update.huaweiyuncdn.com" nocase
        $domain42 = "cdn7s65.z13.web.core.windows.net" nocase
        $domain43 = "concreteinportland.com" nocase
        $domain44 = "conflictaslesson.com" nocase
        $domain45 = "connectmvasalu.cam" nocase
        $domain46 = "constructionferryfences.cam" nocase
        $domain47 = "coolboxpc.com" nocase
        $domain48 = "couldinstallup.com" nocase
        $domain49 = "csp.document-invoiceviewer.online" nocase
        $domain50 = "csp.document-viewer.xyz" nocase
        $domain51 = "csp.documentpdfviewer.xyz" nocase
        $domain52 = "csp.office-docs.online" nocase
        $domain53 = "d32tpl7xt7175h.cloudfront.net" nocase
        $domain54 = "daydreamdew.net" nocase
        $domain55 = "deleted.tripadviso.online" nocase
        $domain56 = "dest-working.com" nocase
        $domain57 = "destroy2013.com" nocase
        $domain58 = "devlyrics.com" nocase
        $domain59 = "devlyrics.github.io" nocase
        $domain60 = "dl6yfsl.com" nocase
        $domain61 = "dljmp2p.com" nocase
        $domain62 = "document-invoiceviewer.online" nocase
        $domain63 = "document-viewer.xyz" nocase
        $domain64 = "documentinvoice-viewer.top" nocase
        $domain65 = "documentpdfviewer.xyz" nocase
        $domain66 = "dodefoh.com" nocase
        $domain67 = "download.flach.cn" nocase
        $domain68 = "download.hilifimyanmar.com" nocase
        $domain69 = "drive.babyafrosapparel.com" nocase
        $domain70 = "editor.gleeze.com" nocase
        $domain71 = "electrictulsa.com" nocase
        $domain72 = "em2in.johnsimde.xyz" nocase
        $domain73 = "estmongolia.com" nocase
        $domain74 = "events.api.document-invoiceviewer.online" nocase
        $domain75 = "events.api.document-viewer.xyz" nocase
        $domain76 = "events.api.office-docs.online" nocase
        $domain77 = "ferryfences.cam" nocase
        $domain78 = "ferryfencesconstruc.cam" nocase
        $domain79 = "ferryfencesconstruction.cam" nocase
        $domain80 = "fil76v6shar604bbdoc0o.com" nocase
        $domain81 = "fileclub.modaestilo.net" nocase
        $domain82 = "files.document-invoiceviewer.online" nocase
        $domain83 = "files.document-viewer.xyz" nocase
        $domain84 = "files.documentpdfviewer.xyz" nocase
        $domain85 = "files.office-docs.online" nocase
        $domain86 = "files.office3-docviewer.com" nocase
        $domain87 = "files.riddhiman.shop" nocase
        $domain88 = "filesdownld.z13.web.core.windows.net" nocase
        $domain89 = "fileshare.babyafrosapparel.com" nocase
        $domain90 = "fileshare.gorollerskate.com" nocase
        $domain91 = "filestoretome.z23.web.core.windows.net" nocase
        $domain92 = "filevault.soundit.co" nocase
        $domain93 = "fitehook.com" nocase
        $domain94 = "fjke5oe.com" nocase
        $domain95 = "flach.cn" nocase
        $domain96 = "flash-update.buyonebuy.top" nocase
        $domain97 = "flowise.document-viewer.xyz" nocase
        $domain98 = "forexdualsystem.com" nocase
        $domain99 = "formainservercheap.com" nocase
        $ip100 = "102.211.234.105"
        $ip101 = "103.107.104.37"
        $ip102 = "103.107.104.61"
        $ip103 = "103.107.104.61"
        $ip104 = "103.13.31.75"
        $ip105 = "103.15.28.145"
        $ip106 = "103.15.29.17"
        $ip107 = "103.159.132.80"
        $ip108 = "103.175.50.32"
        $ip109 = "103.192.226.46"
        $ip110 = "103.200.97.189"
        $ip111 = "103.200.97.189"
        $ip112 = "103.245.164.154"
        $ip113 = "103.247.19.204"
        $ip114 = "103.249.84.137"
        $ip115 = "103.27.109.157"
        $ip116 = "103.56.18.101"
        $ip117 = "103.56.18.101"
        $ip118 = "103.56.53.120"
        $ip119 = "103.79.120.70"
        $ip120 = "103.79.120.70"
        $ip121 = "103.79.120.71"
        $ip122 = "103.79.120.71"
        $ip123 = "103.79.120.73"
        $ip124 = "103.79.120.73"
        $ip125 = "103.79.120.74"
        $ip126 = "103.79.120.74"
        $ip127 = "103.79.120.81"
        $ip128 = "103.79.120.81"
        $ip129 = "103.79.120.85"
        $ip130 = "103.79.120.89"
        $ip131 = "103.79.77.181"
        $ip132 = "104.194.154.150"
        $ip133 = "107.155.56.87"
        $ip134 = "107.155.56.87"
        $ip135 = "107.181.160.16"
        $ip136 = "110.42.64.64"
        $ip137 = "123.253.32.15"
        $ip138 = "136.0.141.189"
        $ip139 = "136.0.141.189"
        $ip140 = "136.0.141.189"
        $ip141 = "139.180.192.163"
        $ip142 = "139.180.192.163"
        $ip143 = "139.180.217.142"
        $ip144 = "139.59.46.88"
        $ip145 = "139.59.46.88"
        $ip146 = "139.59.46.88"
        $ip147 = "139.59.46.88"
        $ip148 = "146.70.149.186"
        $ip149 = "146.70.149.36"

    condition:
        any of them
}

rule APT_NAIKON {
    meta:
        description = "Indicators associated with APT NAIKON"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "deadringer"

    strings:
        $domain0 = "a.jrmfeeder.org" nocase
        $domain1 = "afhkl.dseqoorg.com" nocase
        $domain2 = "ahzx.eicp.net" nocase
        $domain3 = "ajtkgygth.com" nocase
        $domain4 = "aloha.fekeigawy.com" nocase
        $domain5 = "articles.whynotad.com" nocase
        $domain6 = "asp.asphspes.com" nocase
        $domain7 = "asphspes.com" nocase
        $domain8 = "bbs.forcejoyt.com" nocase
        $domain9 = "bkav.imshop.in" nocase
        $domain10 = "blog.toptogear.com" nocase
        $domain11 = "cat.suttiphong.com" nocase
        $domain12 = "cent.myanmarnewsrecent.com" nocase
        $domain13 = "cpc.mashresearchb.com" nocase
        $domain14 = "dathktdga.com" nocase
        $domain15 = "dgwktifrn.com" nocase
        $domain16 = "dns.jmrmfitym.com" nocase
        $domain17 = "dns.seekvibega.com" nocase
        $domain18 = "dthjxc.com" nocase
        $domain19 = "familymart-pay.cc" nocase
        $domain20 = "fekeigawy.com" nocase
        $domain21 = "freebsd.extrimtur.com" nocase
        $domain22 = "googlemm.vicp.net" nocase
        $domain23 = "guaranteed9.strangled.net" nocase
        $domain24 = "hosts.mysaol.com" nocase
        $domain25 = "http.jmrmfitym.com" nocase
        $domain26 = "imgs09.homenet.org" nocase
        $domain27 = "java.tripadvisorsapp.com" nocase
        $domain28 = "jdk.gsvvfsso.com" nocase
        $domain29 = "jmrmfitym.com" nocase
        $domain30 = "kyawtun119.com" nocase
        $domain31 = "kyemtyjah.com" nocase
        $domain32 = "mail.tripadvisorsapp.com" nocase
        $domain33 = "mncgn.51vip.biz" nocase
        $domain34 = "mon-enews.com" nocase
        $domain35 = "my.eiyfmrn.com" nocase
        $domain36 = "myanmarnewsrecent.com" nocase
        $domain37 = "myanmartech.vicp.net" nocase
        $domain38 = "n91t78dxr3.com" nocase
        $domain39 = "news.dgwktifrn.com" nocase
        $domain40 = "news.nyhedmgtxck.com" nocase
        $domain41 = "nw.eiyfmrn.com" nocase
        $domain42 = "osde.twifwkeyh.com" nocase
        $domain43 = "php.tripadvisorsapp.com" nocase
        $domain44 = "qisxnikm.com" nocase
        $domain45 = "rad.geewkmy.com" nocase
        $domain46 = "realteks.gjdredj.com" nocase
        $domain47 = "rrgwmmwgk.com" nocase
        $domain48 = "second.photo-frame.com" nocase
        $domain49 = "seekvibega.com" nocase
        $domain50 = "spool.jtjewifyn.com" nocase
        $domain51 = "sugano.trictalmk.com" nocase
        $domain52 = "suttiphong.com" nocase
        $domain53 = "thailand.vicp.net" nocase
        $domain54 = "tnelgnmc.com" nocase
        $domain55 = "tripadvisorsapp.com" nocase
        $domain56 = "ttareyice.jkub.com" nocase
        $domain57 = "twifwkeyh.com" nocase
        $domain58 = "ubaoyouxiang.gicp.net" nocase
        $domain59 = "vietnam.gnway.net" nocase
        $domain60 = "wahatmrjn.com" nocase
        $domain61 = "wdrfjkg129.com" nocase
        $domain62 = "web01.crabdance.com" nocase
        $ip63 = "124.156.241.24"
        $ip64 = "150.109.178.252"
        $ip65 = "150.109.178.252"
        $ip66 = "150.109.178.252"
        $ip67 = "150.109.178.252"
        $ip68 = "150.109.178.252"
        $ip69 = "150.109.178.252"
        $ip70 = "150.109.178.252"
        $ip71 = "150.109.178.252"
        $ip72 = "150.109.178.252"
        $ip73 = "150.109.178.252"
        $ip74 = "150.109.184.127"
        $ip75 = "150.109.184.127"
        $ip76 = "150.109.184.127"
        $ip77 = "150.109.184.127"
        $ip78 = "150.109.184.127"
        $ip79 = "150.109.184.127"
        $ip80 = "150.109.184.127"
        $ip81 = "150.109.184.127"
        $ip82 = "150.109.184.127"
        $ip83 = "47.241.127.190"

    condition:
        any of them
}

rule APT_NETTRAVELER {
    meta:
        description = "Indicators associated with APT NETTRAVELER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "allen.w223.west263.cn" nocase
        $domain1 = "andriodphone.net" nocase
        $domain2 = "bauer.8866.org" nocase
        $domain3 = "buynewes.com" nocase
        $domain4 = "cultureacess.com" nocase
        $domain5 = "discoverypeace.org" nocase
        $domain6 = "drag2008.com" nocase
        $domain7 = "eaglesey.com" nocase
        $domain8 = "enterairment.net" nocase
        $domain9 = "gami1.com" nocase
        $domain10 = "globalmailru.com" nocase
        $domain11 = "hint09.9966.org" nocase
        $domain12 = "imapupdate.com" nocase
        $domain13 = "info-spb.com" nocase
        $domain14 = "interfaxru.com" nocase
        $domain15 = "inwpvpn.com" nocase
        $domain16 = "keyboardhk.com" nocase
        $domain17 = "localgroupnet.com" nocase
        $domain18 = "mailyandexru.com" nocase
        $domain19 = "mogoogle.com" nocase
        $domain20 = "msnnewes.com" nocase
        $domain21 = "newesyahoo.com" nocase
        $domain22 = "newfax.net" nocase
        $domain23 = "pkspring.net" nocase
        $domain24 = "ra1nru.com" nocase
        $domain25 = "ramb1er.com" nocase
        $domain26 = "riaru.net" nocase
        $domain27 = "sghrhd.190.20081.info" nocase
        $domain28 = "southstock.net" nocase
        $domain29 = "spit113.minidns.net" nocase
        $domain30 = "tassnews.net" nocase
        $domain31 = "tsgoogoo.net" nocase
        $domain32 = "vip222idc.s169.288idc.com" nocase
        $domain33 = "viplenta.com" nocase
        $domain34 = "vipmailru.com" nocase
        $domain35 = "viprainru.com" nocase
        $domain36 = "viprambler.com" nocase
        $domain37 = "vipyandex.com" nocase
        $domain38 = "voennovosti.com" nocase
        $domain39 = "vpnwork.3322.org" nocase
        $domain40 = "wolf0.3322.org" nocase
        $domain41 = "wolf001.us109.eoidc.net" nocase
        $domain42 = "yahooair.com" nocase
        $domain43 = "yangdex.org" nocase
        $domain44 = "zeroicelee.com" nocase

    condition:
        any of them
}

rule APT_NEWSBEEF {
    meta:
        description = "Indicators associated with APT NEWSBEEF"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "cloud.services-mozilla.com" nocase
        $domain1 = "msservice.site" nocase
        $domain2 = "service.chrome-up.date" nocase
        $domain3 = "service1.chrome-up.date" nocase
        $domain4 = "webmaster.serveirc.com" nocase
        $domain5 = "www.chrome-up.date" nocase

    condition:
        any of them
}

rule APT_NEWSPENGUIN {
    meta:
        description = "Indicators associated with APT NEWSPENGUIN"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "updates.win32.live" nocase
        $domain1 = "win32.live" nocase
        $domain2 = "windowsupdates.shop" nocase

    condition:
        any of them
}

rule APT_NIGHTEAGLE {
    meta:
        description = "Indicators associated with APT NIGHTEAGLE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "APT-Q-95"

    strings:
        $domain0 = "app.flowgw.com" nocase
        $domain1 = "ccproxy.org" nocase
        $domain2 = "cloud.synologyupdates.com" nocase
        $domain3 = "comfyupdate.org" nocase
        $domain4 = "coremailtech.com" nocase
        $domain5 = "daihou360.com" nocase
        $domain6 = "dashboard.daihou360.com" nocase
        $domain7 = "doubleclicked.com" nocase
        $domain8 = "e-mailrelay.com" nocase
        $domain9 = "fastapi-cdn.com" nocase
        $domain10 = "flowgw.com" nocase
        $domain11 = "fortisys.net" nocase
        $domain12 = "haprxy.org" nocase
        $domain13 = "liveupdate.wsupdatecloud.net" nocase
        $domain14 = "lvusdupdates.org" nocase
        $domain15 = "mirror1.mirrors-openjdk.org" nocase
        $domain16 = "mirrors-openjdk.org" nocase
        $domain17 = "ms-nipre.com" nocase
        $domain18 = "ms.wsupdatecloud.net" nocase
        $domain19 = "rhel.lvusdupdates.org" nocase
        $domain20 = "sangsoft.net" nocase
        $domain21 = "saperpcloud.com" nocase
        $domain22 = "shangjuyike.com" nocase
        $domain23 = "synologyupdates.com" nocase
        $domain24 = "threatbookav.com" nocase
        $domain25 = "tracking.doubleclicked.com" nocase
        $domain26 = "update.haprxy.org" nocase
        $domain27 = "update.saperpcloud.com" nocase
        $domain28 = "updates.ccproxy.org" nocase
        $domain29 = "wechatutilities.com" nocase
        $domain30 = "wsupdatecloud.net" nocase

    condition:
        any of them
}

rule APT_NOISYBEAR {
    meta:
        description = "Indicators associated with APT NOISYBEAR"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "wellfitplan.ru" nocase
        $ip1 = "178.159.94.8"
        $ip2 = "77.239.125.41"
        $ip3 = "77.239.125.41"

    condition:
        any of them
}

rule APT_NONAME05716 {
    meta:
        description = "Indicators associated with APT NONAME05716"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "bobik, ddosia, killnet"

    strings:
        $domain0 = "beaconbeagle.com" nocase
        $domain1 = "ftp.beaconbeagle.com" nocase
        $domain2 = "ftp.minimedusa.lol" nocase
        $domain3 = "minimedusa.lol" nocase
        $domain4 = "q7zemy6zc7ptaeks.servehttp.com" nocase
        $domain5 = "tom56gaz6poh13f28.myftp.org" nocase
        $domain6 = "v9agm8uwtjmz.sytes.net" nocase
        $domain7 = "witha.name" nocase
        $domain8 = "withanamemwesdvodfhthjq25a5a3uas24cpgoa7qm6gchcerzpis6qd.onion" nocase
        $domain9 = "zig35m48zur14nel40.myftp.org" nocase
        $ip10 = "109.107.181.130"
        $ip11 = "109.107.181.130"
        $ip12 = "109.107.184.11"
        $ip13 = "161.35.199.2"
        $ip14 = "161.35.199.2"
        $ip15 = "185.173.37.220"
        $ip16 = "185.173.37.220"
        $ip17 = "31.13.195.87"
        $ip18 = "77.91.66.85"
        $ip19 = "77.91.66.85"
        $ip20 = "87.121.52.9"
        $ip21 = "87.121.52.9"
        $ip22 = "91.142.79.201"
        $ip23 = "91.142.79.201"
        $ip24 = "94.140.114.239"
        $ip25 = "94.140.114.239"
        $ip26 = "94.140.115.129"
        $ip27 = "94.140.115.129"

    condition:
        any of them
}

rule APT_NOVISPY {
    meta:
        description = "Indicators associated with APT NOVISPY"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "185.86.148.174"

    condition:
        any of them
}

rule APT_OBSMOGWAI {
    meta:
        description = "Indicators associated with APT OBSMOGWAI"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "dimanorat, donnect, trochilusrat"

    strings:
        $domain0 = "cariolis.com" nocase
        $domain1 = "dns-stream.com" nocase
        $domain2 = "down.soft-update.com" nocase
        $domain3 = "down.softupdate.com" nocase
        $domain4 = "go.thejra.com" nocase
        $domain5 = "help.springnow.net" nocase
        $domain6 = "home.thejra.com" nocase
        $domain7 = "hoteldinamo.com" nocase
        $domain8 = "hy.indiatopsite.com" nocase
        $domain9 = "imail.indiatopsite.com" nocase
        $domain10 = "indiatopsite.com" nocase
        $domain11 = "iss-tass.com" nocase
        $domain12 = "lion.thejra.com" nocase
        $domain13 = "macbook.thejra.com" nocase
        $domain14 = "my.thejra.com" nocase
        $domain15 = "parking.samogony.com" nocase
        $domain16 = "pitmanbed.space" nocase
        $domain17 = "puzirik.com" nocase
        $domain18 = "reformamebel.com" nocase
        $domain19 = "rhodesauto.space" nocase
        $domain20 = "rralphfood.space" nocase
        $domain21 = "seanpi.thejra.com" nocase
        $domain22 = "secure.thejra.com" nocase
        $domain23 = "skypi.thejra.com" nocase
        $domain24 = "soft-update.com" nocase
        $domain25 = "softupdate.com" nocase
        $domain26 = "ssl.hoteldinamo.com" nocase
        $domain27 = "tes.indiatopsite.com" nocase
        $domain28 = "ttl.huzfs.com" nocase
        $domain29 = "vorots.ru" nocase
        $domain30 = "yandexcloud.samogony.com" nocase
        $ip31 = "108.160.136.200"
        $ip32 = "116.251.217.104"
        $ip33 = "122.192.11.114"
        $ip34 = "122.96.34.142"
        $ip35 = "139.162.111.143"
        $ip36 = "139.84.139.176"
        $ip37 = "149.28.189.102"
        $ip38 = "158.247.203.87"
        $ip39 = "181.215.229.119"
        $ip40 = "185.132.125.154"
        $ip41 = "185.167.116.30"
        $ip42 = "185.4.66.116"
        $ip43 = "188.116.22.90"
        $ip44 = "188.130.160.144"
        $ip45 = "192.121.171.190"
        $ip46 = "192.121.47.214"
        $ip47 = "192.248.153.215"
        $ip48 = "193.47.34.229"
        $ip49 = "194.68.26.142"
        $ip50 = "194.68.26.164"
        $ip51 = "213.135.67.198"
        $ip52 = "213.183.54.200"
        $ip53 = "213.183.56.238"
        $ip54 = "213.183.57.73"
        $ip55 = "27.102.115.153"
        $ip56 = "31.192.234.35"
        $ip57 = "31.214.157.5"
        $ip58 = "38.180.29.3"
        $ip59 = "38.54.16.120"
        $ip60 = "45.12.67.18"
        $ip61 = "45.150.64.23"
        $ip62 = "46.161.15.98"
        $ip63 = "46.8.43.28"
        $ip64 = "5.188.33.50"
        $ip65 = "5.8.33.45"
        $ip66 = "51.79.191.204"
        $ip67 = "85.159.208.143"
        $ip68 = "86.105.227.126"
        $ip69 = "86.106.102.119"
        $ip70 = "92.119.159.22"
        $ip71 = "92.243.66.166"
        $ip72 = "92.38.160.212"
        $ip73 = "92.38.160.7"
        $ip74 = "94.177.123.215"
        $ip75 = "95.179.249.142"

    condition:
        any of them
}

rule APT_OCEANLOTUS {
    meta:
        description = "Indicators associated with APT OCEANLOTUS"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt32, apt-c-00, apt-c-32"

    strings:
        $domain0 = "0b3l1sk.me" nocase
        $domain1 = "163mailservice.com" nocase
        $domain2 = "24.datatimes.org" nocase
        $domain3 = "360skylar.host" nocase
        $domain4 = "365.urielcallum.com" nocase
        $domain5 = "accounts.getmyip.com" nocase
        $domain6 = "ad.ssageevrenue.com" nocase
        $domain7 = "adineohler.com" nocase
        $domain8 = "adobe.riceaub.com" nocase
        $domain9 = "agoras.hopto.org" nocase
        $domain10 = "agoras.zapto.org" nocase
        $domain11 = "aisicoin.com" nocase
        $domain12 = "aki.viperse.com" nocase
        $domain13 = "alicervois.com" nocase
        $domain14 = "aliexpresscn.net" nocase
        $domain15 = "alyerrac.com" nocase
        $domain16 = "anaehler.com" nocase
        $domain17 = "andreafaerber.com" nocase
        $domain18 = "andreagahuvrauvin.com" nocase
        $domain19 = "andreagbridge.com" nocase
        $domain20 = "anessallie.com" nocase
        $domain21 = "annamerrett.com" nocase
        $domain22 = "anofrio.com" nocase
        $domain23 = "antenham.com" nocase
        $domain24 = "aol.straliaenollma.xyz" nocase
        $domain25 = "api.anaehler.com" nocase
        $domain26 = "api.blogdns.com" nocase
        $domain27 = "api.ciscofreak.com" nocase
        $domain28 = "api.myddns.me" nocase
        $domain29 = "apiservice.webhop.net" nocase
        $domain30 = "arbenha.com" nocase
        $domain31 = "arinaurna.com" nocase
        $domain32 = "arkoimmerma.com" nocase
        $domain33 = "art.guillermoespana.com" nocase
        $domain34 = "art.yfieldrainasch.com" nocase
        $domain35 = "asia-kotoba.net" nocase
        $domain36 = "att.illagedrivestralia.xyz" nocase
        $domain37 = "au.charlineopkesston.com" nocase
        $domain38 = "audreybourgeois.com" nocase
        $domain39 = "aulolloy.com" nocase
        $domain40 = "auth.lineage2ez.com" nocase
        $domain41 = "avidilleneu.com" nocase
        $domain42 = "avidsontre.com" nocase
        $domain43 = "aximilian.com" nocase
        $domain44 = "b.cortanazone.com" nocase
        $domain45 = "background.ristians.com" nocase
        $domain46 = "baidu-search.net" nocase
        $domain47 = "baodachieu.com" nocase
        $domain48 = "baomoivietnam.com" nocase
        $domain49 = "base.msteamsapi.com" nocase
        $domain50 = "beaudrysang.xyz" nocase
        $domain51 = "beautifull-font.salebusinesend.com" nocase
        $domain52 = "becreybour.com" nocase
        $domain53 = "benjamiilliams.club" nocase
        $domain54 = "benjamiilliams.icu" nocase
        $domain55 = "beta.officopedia.com" nocase
        $domain56 = "biasatts.com" nocase
        $domain57 = "bit.catalinabonami.com" nocase
        $domain58 = "blank.eatherurg.com" nocase
        $domain59 = "blog.artinhauvin.com" nocase
        $domain60 = "blog.docksugs.org" nocase
        $domain61 = "blog.eduelects.com" nocase
        $domain62 = "blog.panggin.org" nocase
        $domain63 = "bluesky2018man.com" nocase
        $domain64 = "bmw-corp.net" nocase
        $domain65 = "bmwthailand.org" nocase
        $domain66 = "braydenhateaub.com" nocase
        $domain67 = "bucket.serveftp.net" nocase
        $domain68 = "bussinesappinstant.com" nocase
        $domain69 = "byronorenstein.com" nocase
        $domain70 = "carosseda.com" nocase
        $domain71 = "cbo.group" nocase
        $domain72 = "cctv.avidsonec.com" nocase
        $domain73 = "cdn.arlialter.com" nocase
        $domain74 = "cdn.eworldship-news.com" nocase
        $domain75 = "cdn.mirror-codes.net" nocase
        $domain76 = "cdn.redirectme.net" nocase
        $domain77 = "cdn3.onlinesurveygorilla.com" nocase
        $domain78 = "cdnwebmedia.com" nocase
        $domain79 = "cds55.lax8.setalz.com" nocase
        $domain80 = "cert.opennetworklab.com" nocase
        $domain81 = "chart.expocasheuro.com" nocase
        $domain82 = "chascloud.com" nocase
        $domain83 = "check.homeip.net" nocase
        $domain84 = "check.paidprefund.org" nocase
        $domain85 = "check.webhop.org" nocase
        $domain86 = "chinaport.org" nocase
        $domain87 = "christienoll.xyz" nocase
        $domain88 = "christienollmache.xyz" nocase
        $domain89 = "ckoen.dmkatti.com" nocase
        $domain90 = "clip.shangweidesign.com" nocase
        $domain91 = "clipboard.christienoll.xyz" nocase
        $domain92 = "cloud.360cn.info" nocase
        $domain93 = "cloud.anofrio.com" nocase
        $domain94 = "cloud.bussinesappinstant.com" nocase
        $domain95 = "cloud.chinatel.org" nocase
        $domain96 = "cloud.doomdns.org" nocase
        $domain97 = "cloud.reneark.com" nocase
        $domain98 = "cloud.sicaogler.com" nocase
        $domain99 = "clouds.onthewifi.com" nocase
        $ip100 = "103.91.67.74"
        $ip101 = "109.107.171.113"
        $ip102 = "109.107.171.113"
        $ip103 = "109.107.171.113"
        $ip104 = "139.59.30.109"
        $ip105 = "144.202.46.221"
        $ip106 = "152.32.144.5"
        $ip107 = "154.93.37.106"
        $ip108 = "160.86.38.21"
        $ip109 = "178.255.220.115"
        $ip110 = "185.161.208.105"
        $ip111 = "185.161.208.105"
        $ip112 = "185.198.57.184"
        $ip113 = "185.225.19.100"
        $ip114 = "185.43.220.188"
        $ip115 = "185.82.126.4"
        $ip116 = "190.211.254.203"
        $ip117 = "193.138.195.192"
        $ip118 = "195.12.50.172"
        $ip119 = "202.59.10.170"
        $ip120 = "221.219.213.178"
        $ip121 = "43.254.132.117"
        $ip122 = "43.254.132.212"
        $ip123 = "45.41.204.15"
        $ip124 = "45.41.204.18"
        $ip125 = "45.61.139.211"
        $ip126 = "45.63.123.237"

    condition:
        any of them
}

rule APT_OILALPHA {
    meta:
        description = "Indicators associated with APT OILALPHA"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "2020anekafkark2020.ddns.net" nocase
        $domain1 = "712175206totot.ddns.net" nocase
        $domain2 = "77112hilan.ddns.net" nocase
        $domain3 = "87524uyre.ddns.net" nocase
        $domain4 = "abas1.ddns.net" nocase
        $domain5 = "akjdaks54678sdas.ddns.net" nocase
        $domain6 = "antahomaar2022.ddns.net" nocase
        $domain7 = "bobkkfoundationyemen2022.ddns.net" nocase
        $domain8 = "bobm1jgjahsg81.ddns.net" nocase
        $domain9 = "dhgrshghjrsg0092102.ddns.net" nocase
        $domain10 = "djhgurjhwdskh72532.ddns.me" nocase
        $domain11 = "goman239.ddns.net" nocase
        $domain12 = "gomnd2873yemnenrc.ddns.net" nocase
        $domain13 = "hilan77112.ddns.net" nocase
        $domain14 = "hjsdg2368gskambv.ddns.net" nocase
        $domain15 = "hm712175206zh.ddns.net" nocase
        $domain16 = "hsdg763276jgkjx.ddns.net" nocase
        $domain17 = "hsgdjh78632.mypsx.net" nocase
        $domain18 = "magtimego.servegame.com" nocase
        $domain19 = "manyouhomaar21.ddns.net" nocase
        $domain20 = "moonname2022.ddns.net" nocase
        $domain21 = "musicmatrix.access.ly" nocase
        $domain22 = "ncbyemen2008.ddns.net" nocase
        $domain23 = "ndf236fgh4367h.ddns.net" nocase
        $domain24 = "saaoff33993homhl.ddns.net" nocase
        $domain25 = "saudigazette2022yemen.ddns.net" nocase
        $domain26 = "yemenofoneofline.ddns.net" nocase
        $domain27 = "you7788mtnq.ddns.net" nocase

    condition:
        any of them
}

rule APT_OILRIG {
    meta:
        description = "Indicators associated with APT OILRIG"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt34, oilrig, helixkitten"

    strings:
        $domain0 = "262t3my0gt.cardioteacher.com" nocase
        $domain1 = "2fhj.asiaworldremit.com" nocase
        $domain2 = "2u21hipg70.uber-asia.com" nocase
        $domain3 = "2zcf.uber-asia.com" nocase
        $domain4 = "3j3oyvsf8i.joexpediagroup.com" nocase
        $domain5 = "5s5gp24f8x.asiaworldremit.com" nocase
        $domain6 = "6google.com" nocase
        $domain7 = "7a7n4j60g4.cardioteacher.com" nocase
        $domain8 = "7w7rbgt13f.uber-asia.com" nocase
        $domain9 = "ababab.biz" nocase
        $domain10 = "acceptplan.com" nocase
        $domain11 = "acrlee.com" nocase
        $domain12 = "acrobatverify.com" nocase
        $domain13 = "admin.mofaiq.com" nocase
        $domain14 = "akamai-global.com" nocase
        $domain15 = "akastatus.com" nocase
        $domain16 = "alcirineos.com" nocase
        $domain17 = "alforatsystem.com" nocase
        $domain18 = "allsecpackupdater.com" nocase
        $domain19 = "amazon-loveyou.com" nocase
        $domain20 = "anhuisiafu.com" nocase
        $domain21 = "antivirus-update.top" nocase
        $domain22 = "anyportals.com" nocase
        $domain23 = "applicationframehost.in" nocase
        $domain24 = "apps.iqwebservice.com" nocase
        $domain25 = "asiacall.net" nocase
        $domain26 = "asiaworldremit.com" nocase
        $domain27 = "astrazencea.com" nocase
        $domain28 = "astrazeneeca.com" nocase
        $domain29 = "axoryvexity.eu" nocase
        $domain30 = "bargertextiles.com" nocase
        $domain31 = "base32.iqwebservice.com" nocase
        $domain32 = "berqertextiles.com" nocase
        $domain33 = "bgre.kozow.com" nocase
        $domain34 = "biam-iraq.org" nocase
        $domain35 = "boardexecutivemanagement.com" nocase
        $domain36 = "boardsexecutives.com" nocase
        $domain37 = "cam-research-ac.com" nocase
        $domain38 = "cardioteacher.com" nocase
        $domain39 = "careers-ntiva.com" nocase
        $domain40 = "cdn-edge-akamai.com" nocase
        $domain41 = "cererock.com" nocase
        $domain42 = "chinaconstructioncorp.com" nocase
        $domain43 = "chrome-dns.com" nocase
        $domain44 = "cisco0.com" nocase
        $domain45 = "clearinghouseinternational.com" nocase
        $domain46 = "cloudipnameserver.com" nocase
        $domain47 = "coinbasedeutschland.com" nocase
        $domain48 = "coldflys.com" nocase
        $domain49 = "confusedtown.com" nocase
        $domain50 = "connect-roofing.com" nocase
        $domain51 = "cornerstoneconect.com" nocase
        $domain52 = "cpuproc.com" nocase
        $domain53 = "crucialanswer.com" nocase
        $domain54 = "defender-update.com" nocase
        $domain55 = "digi.shanx.icu" nocase
        $domain56 = "dns-update.club" nocase
        $domain57 = "dnsupdateservers.net" nocase
        $domain58 = "donotfollowmeass.com" nocase
        $domain59 = "efezhyrzc9.joexpediagroup.com" nocase
        $domain60 = "egef74rfrf.cardioteacher.com" nocase
        $domain61 = "endlesspromises.com" nocase
        $domain62 = "exmngt.com" nocase
        $domain63 = "fastasia.shop" nocase
        $domain64 = "ffconnectivitycheck.com" nocase
        $domain65 = "fireeyeupdate.com" nocase
        $domain66 = "firewallsupports.com" nocase
        $domain67 = "flowconnectivity.com" nocase
        $domain68 = "forecasterman.com" nocase
        $domain69 = "fuktheme.com" nocase
        $domain70 = "go0gIe.com" nocase
        $domain71 = "godoycrus.com" nocase
        $domain72 = "googie.email" nocase
        $domain73 = "google-update.com" nocase
        $domain74 = "googleupdate.download" nocase
        $domain75 = "goosegoosecome.com" nocase
        $domain76 = "greenkeyllc-projects.com" nocase
        $domain77 = "groupsexecutive.com" nocase
        $domain78 = "herkhabar.com" nocase
        $domain79 = "hoganlouells.com" nocase
        $domain80 = "hopeisstamina.com" nocase
        $domain81 = "hpserver.online" nocase
        $domain82 = "hr-westat.com" nocase
        $domain83 = "hsbcbkcn.com" nocase
        $domain84 = "hscminkjet.com" nocase
        $domain85 = "hugebricks.com" nocase
        $domain86 = "huopay.top" nocase
        $domain87 = "importantgate.com" nocase
        $domain88 = "indeptheva.com" nocase
        $domain89 = "infopulsejobs.com" nocase
        $domain90 = "intelligent-finance.site" nocase
        $domain91 = "iqwebservice.com" nocase
        $domain92 = "iraqmailservice.com" nocase
        $domain93 = "j9jnkf7asv.joexpediagroup.com" nocase
        $domain94 = "jiabolianjie0.com" nocase
        $domain95 = "jinkangpu.co" nocase
        $domain96 = "jlrootfile.com" nocase
        $domain97 = "joexpediagroup.com" nocase
        $domain98 = "jqj6po1g71.uber-asia.com" nocase
        $domain99 = "kent-lawfirm.net" nocase
        $ip100 = "151.236.17.231"
        $ip101 = "151.236.17.231"
        $ip102 = "151.236.17.231"
        $ip103 = "185.198.59.121"
        $ip104 = "185.198.59.121"
        $ip105 = "185.198.59.121"
        $ip106 = "185.32.178.176"
        $ip107 = "185.76.78.177"
        $ip108 = "185.76.78.177"
        $ip109 = "185.76.78.177"
        $ip110 = "185.76.78.177"
        $ip111 = "192.71.166.24"
        $ip112 = "193.36.132.224"
        $ip113 = "194.68.32.114"
        $ip114 = "198.44.140.29"
        $ip115 = "198.44.140.29"
        $ip116 = "206.206.123.176"
        $ip117 = "206.206.123.176"
        $ip118 = "37.1.213.152"
        $ip119 = "37.1.213.152"
        $ip120 = "38.180.140.30"
        $ip121 = "38.180.18.189"
        $ip122 = "38.180.31.225"
        $ip123 = "38.180.31.225"
        $ip124 = "89.46.233.239"
        $ip125 = "89.46.233.239"
        $ip126 = "91.132.95.117"
        $ip127 = "91.132.95.117"
        $ip128 = "91.132.95.117"
        $ip129 = "91.132.95.117"
        $ip130 = "91.184.249.198"
        $ip131 = "93.177.75.180"
        $ip132 = "95.156.204.168"
        $ip133 = "95.156.204.168"
        $ip134 = "95.156.204.168"
        $ip135 = "95.211.104.253"
        $ip136 = "95.211.104.253"
        $ip137 = "95.211.104.253"
        $ip138 = "95.211.210.55"
        $ip139 = "95.211.213.168"
        $ip140 = "95.211.213.177"
        $ip141 = "95.211.215.225"

    condition:
        any of them
}

rule APT_ONYXSLEET {
    meta:
        description = "Indicators associated with APT ONYXSLEET"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "147.78.149.201"
        $ip1 = "162.19.71.175"

    condition:
        any of them
}

rule APT_OPERA1ER {
    meta:
        description = "Indicators associated with APT OPERA1ER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "bluebottle, commonraven, desktop group"

    strings:
        $domain0 = "4x33.ignorelist.com" nocase
        $domain1 = "actu.afrikmedia.info" nocase
        $domain2 = "actu.banquealtantique.net" nocase
        $domain3 = "afijoh.net" nocase
        $domain4 = "afrikmedia.info" nocase
        $domain5 = "bac.eimaragon.org" nocase
        $domain6 = "bac.senegalsante.org" nocase
        $domain7 = "boa.eimaragon.org" nocase
        $domain8 = "cnam.myvnc.com" nocase
        $domain9 = "cobalt.warii.club" nocase
        $domain10 = "codir.ocitnetad.com" nocase
        $domain11 = "contact.senegalsante.org" nocase
        $domain12 = "coris-bank.fr" nocase
        $domain13 = "covid.ocitnetad.com" nocase
        $domain14 = "crazy.senegalsante.org" nocase
        $domain15 = "dc-4ade33bd8726.bdm-sa.fr" nocase
        $domain16 = "direct8.ddns.net" nocase
        $domain17 = "download.nortonupdate.com" nocase
        $domain18 = "driver.eimaragon.org" nocase
        $domain19 = "droid.senegalsante.org" nocase
        $domain20 = "dynastie.warzonedns.com" nocase
        $domain21 = "eimanet.eimaragon.org" nocase
        $domain22 = "eimaragon.org" nocase
        $domain23 = "evamachine.tk" nocase
        $domain24 = "ftp.eimaragon.org" nocase
        $domain25 = "gamevnc.myvnc.com" nocase
        $domain26 = "helpdesk-security.org" nocase
        $domain27 = "hostmaster.senegalsante.org" nocase
        $domain28 = "hunterx1-37009.portmap.io" nocase
        $domain29 = "info.senegalsante.org" nocase
        $domain30 = "info.warii.club" nocase
        $domain31 = "kaspersky-lab.org" nocase
        $domain32 = "kpersky.duckdns.org" nocase
        $domain33 = "mail.mcafee-endpoint.com" nocase
        $domain34 = "mail.warii.club" nocase
        $domain35 = "microsoft-af.com" nocase
        $domain36 = "news.afrikmedia.info" nocase
        $domain37 = "news.coris-bank.fr" nocase
        $domain38 = "noreply.mcafee-endpoint.com" nocase
        $domain39 = "ns.eimaragon.org" nocase
        $domain40 = "ns1.eimaragon.org" nocase
        $domain41 = "ns1.senegalsante.org" nocase
        $domain42 = "ns2.senegalsante.org" nocase
        $domain43 = "ocitnetad.com" nocase
        $domain44 = "operan.ddns.net" nocase
        $domain45 = "personnel.bdm-sa.fr" nocase
        $domain46 = "queen2012.ddns.net" nocase
        $domain47 = "reply2host.duckdns.org" nocase
        $domain48 = "senegalsante.org" nocase
        $domain49 = "server.senegalsante.org" nocase
        $domain50 = "server0.senegalsante.org" nocase
        $domain51 = "server1.senegalsante.org" nocase
        $domain52 = "server2.senegalsante.org" nocase
        $domain53 = "server3.senegalsante.org" nocase
        $domain54 = "serveur1.hopto.org" nocase
        $domain55 = "srvopm.ocitnetad.ci" nocase
        $domain56 = "transmissive-basin.000webhostapp.com" nocase
        $domain57 = "update.kaspersky-lab.org" nocase
        $domain58 = "update.mcafee-endpoint.com" nocase
        $domain59 = "update.microsoft-af.com" nocase
        $domain60 = "utils.afijoh.net" nocase
        $domain61 = "wa.eimaragon.org" nocase
        $domain62 = "wari.warii.club" nocase
        $domain63 = "warii.club" nocase
        $domain64 = "warima.warii.club" nocase
        $domain65 = "webdisk.bdm-sa.fr" nocase
        $domain66 = "windowsdefender.redirectme.net" nocase
        $domain67 = "windowsupgraders.ddns.net" nocase
        $domain68 = "winsec.eimaragon.org" nocase
        $domain69 = "winsec.gotdns.ch" nocase
        $domain70 = "winsec.senegalsante.org" nocase
        $domain71 = "winsec.warii.club" nocase
        $domain72 = "wsus.microsoft-af.com" nocase
        $domain73 = "zfs.life" nocase
        $ip74 = "178.73.192.15"
        $ip75 = "46.246.12.12"
        $ip76 = "46.246.14.17"

    condition:
        any of them
}

rule APT_PACKRAT {
    meta:
        description = "Indicators associated with APT PACKRAT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "conhost.servehttp.com" nocase
        $domain1 = "daynews.sytes.net" nocase
        $domain2 = "deyrep24.ddns.net" nocase
        $domain3 = "dllhost.servehttp.com" nocase
        $domain4 = "lolinha.no-ip.org" nocase
        $domain5 = "ruley.no-ip.org" nocase
        $domain6 = "taskmgr.redirectme.com" nocase
        $domain7 = "taskmgr.serveftp.com" nocase
        $domain8 = "taskmgr.servehttp.com" nocase
        $domain9 = "wjwj.no-ip.org" nocase
        $domain10 = "wjwjwj.no-ip.org" nocase
        $domain11 = "wjwjwjwj.no-ip.org" nocase

    condition:
        any of them
}

rule APT_PAPERWEREWOLF {
    meta:
        description = "Indicators associated with APT PAPERWEREWOLF"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "goffee, echogather"

    strings:
        $domain0 = "arrotech.org" nocase
        $domain1 = "awalitalk.com" nocase
        $domain2 = "certcalc.online" nocase
        $domain3 = "easytrns.com" nocase
        $domain4 = "fast-eda.my" nocase
        $domain5 = "fastchessplay.com" nocase
        $domain6 = "fungaros.com" nocase
        $domain7 = "hakyru.com" nocase
        $domain8 = "jantyroza.com" nocase
        $domain9 = "ntpadjust.online" nocase
        $domain10 = "ntpbayhai.online" nocase
        $domain11 = "ntpcalc.online" nocase
        $domain12 = "ntpchck.online" nocase
        $domain13 = "ntpcheck.online" nocase
        $domain14 = "ntpcorrect.online" nocase
        $domain15 = "ntpedge.online" nocase
        $domain16 = "ntpfetch.online" nocase
        $domain17 = "ntpfix.online" nocase
        $domain18 = "ntpget.online" nocase
        $domain19 = "ntphaiba.online" nocase
        $domain20 = "ntphaimot.online" nocase
        $domain21 = "ntphaisau.online" nocase
        $domain22 = "ntpinform.online" nocase
        $domain23 = "ntpluck.online" nocase
        $domain24 = "ntpmatch.online" nocase
        $domain25 = "ntpmuoitam.online" nocase
        $domain26 = "ntpnet.online" nocase
        $domain27 = "ntpquirks.online" nocase
        $domain28 = "ntpsetup.online" nocase
        $domain29 = "ntpsum.online" nocase
        $domain30 = "ntpsync.online" nocase
        $domain31 = "ntptake.online" nocase
        $domain32 = "ntptop.online" nocase
        $domain33 = "ntptrack.online" nocase
        $domain34 = "ntpverify.online" nocase
        $domain35 = "ntpzone.online" nocase
        $domain36 = "packetflow.online" nocase
        $domain37 = "packethost.online" nocase
        $domain38 = "packetlabs.online" nocase
        $domain39 = "packetread.online" nocase
        $domain40 = "packetsign.online" nocase
        $domain41 = "packettake.online" nocase
        $domain42 = "packetuser.online" nocase
        $domain43 = "packetxhub.online" nocase
        $domain44 = "ruzede.com" nocase
        $domain45 = "sslchck.online" nocase
        $domain46 = "sslcom.online" nocase
        $domain47 = "sslfix.online" nocase
        $domain48 = "sslhttp.online" nocase
        $domain49 = "sslntp.online" nocase
        $domain50 = "sslpack.online" nocase
        $domain51 = "sslpoll.online" nocase
        $domain52 = "sslradio.online" nocase
        $domain53 = "sslreach.online" nocase
        $domain54 = "sslserve.online" nocase
        $domain55 = "sslsign.online" nocase
        $domain56 = "sslstart.online" nocase
        $domain57 = "sslsum.online" nocase
        $domain58 = "ssltail.online" nocase
        $domain59 = "sslteam.online" nocase
        $domain60 = "ssltech.online" nocase
        $domain61 = "ssltick.online" nocase
        $domain62 = "ssltop.online" nocase
        $domain63 = "ssltrade.online" nocase
        $domain64 = "ssltrick.online" nocase
        $domain65 = "ssltun.online" nocase
        $domain66 = "sslvalid.online" nocase
        $domain67 = "timealign.online" nocase
        $domain68 = "timebits.online" nocase
        $domain69 = "timecheck.site" nocase
        $domain70 = "timefetch.online" nocase
        $domain71 = "timeget.cloud" nocase
        $domain72 = "timeget.online" nocase
        $domain73 = "timemaster.site" nocase
        $domain74 = "timematch.online" nocase
        $domain75 = "timemirror.online" nocase
        $domain76 = "timesync.cloud" nocase
        $domain77 = "updatestop.online" nocase
        $domain78 = "woburneast.com" nocase
        $domain79 = "zeccecard.com" nocase

    condition:
        any of them
}

rule APT_PARAGON {
    meta:
        description = "Indicators associated with APT PARAGON"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "bigpretzel, graphite spyware"

    strings:
        $domain0 = "ancient-thing.it" nocase
        $domain1 = "external-astra.com" nocase
        $domain2 = "external-cag.com" nocase
        $domain3 = "external-cap.com" nocase
        $domain4 = "external-drt.com" nocase
        $domain5 = "external-muki.com" nocase
        $domain6 = "external-shotgun3.com" nocase
        $domain7 = "external-sht-prd-4.com" nocase
        $domain8 = "external-sht.com" nocase
        $domain9 = "forti.external-muki.com" nocase
        $domain10 = "forti.external-shotgun3.com" nocase
        $domain11 = "forti.external-sht-prd-4.com" nocase
        $domain12 = "forti.external-sht.com" nocase
        $domain13 = "forti.internal-stg.com" nocase
        $domain14 = "forti.paraccess.com" nocase
        $domain15 = "internal-abba.com" nocase
        $domain16 = "internal-stg.com" nocase
        $domain17 = "modern-money.org" nocase
        $ip18 = "178.237.39.204"
        $ip19 = "178.237.39.204"
        $ip20 = "178.237.39.204"
        $ip21 = "178.237.39.204"
        $ip22 = "194.71.130.218"
        $ip23 = "46.183.184.91"
        $ip24 = "84.110.122.27"
        $ip25 = "84.110.47.82"
        $ip26 = "84.110.47.83"
        $ip27 = "84.110.47.84"
        $ip28 = "84.110.47.84"
        $ip29 = "84.110.47.84"
        $ip30 = "84.110.47.85"
        $ip31 = "84.110.47.85"
        $ip32 = "84.110.47.86"
        $ip33 = "84.110.47.86"
        $ip34 = "84.110.47.86"

    condition:
        any of them
}

rule APT_PATCHWORK {
    meta:
        description = "Indicators associated with APT PATCHWORK"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apachestealer, confucius, patchwork"

    strings:
        $domain0 = "130dozen.com" nocase
        $domain1 = "15731.org" nocase
        $domain2 = "163-cn.org" nocase
        $domain3 = "81-cn.net" nocase
        $domain4 = "a.gyyun.xyz" nocase
        $domain5 = "aaskmee.com" nocase
        $domain6 = "abcvip.us.org" nocase
        $domain7 = "accounts.opensecurity-legacy.com" nocase
        $domain8 = "adaptation-funds.org" nocase
        $domain9 = "adhath-learning.com" nocase
        $domain10 = "adobefileshare.com" nocase
        $domain11 = "adobeonline.org" nocase
        $domain12 = "ados.fyicompsol.xyz" nocase
        $domain13 = "adskochbus.org" nocase
        $domain14 = "alfred.ignorelist.com" nocase
        $domain15 = "alieanmote.live" nocase
        $domain16 = "altered.twilightparadox.com" nocase
        $domain17 = "amelaits.info" nocase
        $domain18 = "anabel.rootranger.info" nocase
        $domain19 = "anchorsoft.org" nocase
        $domain20 = "android-helper.info" nocase
        $domain21 = "anglerrscovey.com" nocase
        $domain22 = "annchenn.com" nocase
        $domain23 = "aonepiece.org" nocase
        $domain24 = "apcas.bhutanembassynepal.com" nocase
        $domain25 = "api.inboundhealthcare.us" nocase
        $domain26 = "api.opensecurity-legacy.com" nocase
        $domain27 = "applepicker.info" nocase
        $domain28 = "appplace.life" nocase
        $domain29 = "apps-house.com" nocase
        $domain30 = "aquilei.live" nocase
        $domain31 = "aquileia.live" nocase
        $domain32 = "arabcomputersupportgroup.com" nocase
        $domain33 = "arkiverat.info" nocase
        $domain34 = "arpawebdom.org" nocase
        $domain35 = "arrayhouse.org" nocase
        $domain36 = "asftbngh.top" nocase
        $domain37 = "asiandefnetwork.com" nocase
        $domain38 = "asustufupdates.com" nocase
        $domain39 = "atus.toproid.xyz" nocase
        $domain40 = "aurorafoss.xyz" nocase
        $domain41 = "auth.fyicompsol.xyz" nocase
        $domain42 = "avangrid.info" nocase
        $domain43 = "avtofrom.us" nocase
        $domain44 = "azureinternalupdates.com" nocase
        $domain45 = "b3autybab3s.com" nocase
        $domain46 = "baidunetdisk.info" nocase
        $domain47 = "balschsteuerix.com" nocase
        $domain48 = "bayanat.co.nf" nocase
        $domain49 = "beautifullimages.co.nf" nocase
        $domain50 = "beijingtv.org" nocase
        $domain51 = "bhutanembassynepal.com" nocase
        $domain52 = "biaonton.insightglobel.info" nocase
        $domain53 = "bilibil.info" nocase
        $domain54 = "bin.opensecurity-legacy.com" nocase
        $domain55 = "bingoplant.live" nocase
        $domain56 = "biwef.rootranger.info" nocase
        $domain57 = "bizzshared.com" nocase
        $domain58 = "blackmoo.info" nocase
        $domain59 = "blingblingg.com" nocase
        $domain60 = "blingin.shop" nocase
        $domain61 = "blingin.xyz" nocase
        $domain62 = "bloomwpp.info" nocase
        $domain63 = "blueberrytree.info" nocase
        $domain64 = "bluechillyboo.site" nocase
        $domain65 = "bluefileshare.com" nocase
        $domain66 = "bluriq.info" nocase
        $domain67 = "bolizhi.info" nocase
        $domain68 = "bolizy.info" nocase
        $domain69 = "bonfo.breatlee.org" nocase
        $domain70 = "bonimoni.xyz" nocase
        $domain71 = "bookerstream.com" nocase
        $domain72 = "bovnle.info" nocase
        $domain73 = "boxmaildrive.info" nocase
        $domain74 = "breachframework.com" nocase
        $domain75 = "breachframework.website" nocase
        $domain76 = "breatlee.org" nocase
        $domain77 = "brightpathos.eu" nocase
        $domain78 = "buzzstack.org" nocase
        $domain79 = "c-cdn77.com" nocase
        $domain80 = "caapakistaan.com" nocase
        $domain81 = "cabinetdivisionpakgov.org" nocase
        $domain82 = "cartmizer.info" nocase
        $domain83 = "cas-cn.org" nocase
        $domain84 = "centling.nihaoucloud.org" nocase
        $domain85 = "cflayerprotection.com" nocase
        $domain86 = "cftn6129.b-cdn.net" nocase
        $domain87 = "charliezard.shop" nocase
        $domain88 = "chatapp-6b96e-default-rtdb.firebaseio.com" nocase
        $domain89 = "chatit.club" nocase
        $domain90 = "chaton.life" nocase
        $domain91 = "chaton.live" nocase
        $domain92 = "chinagreenenergy.org" nocase
        $domain93 = "chinastrat.com" nocase
        $domain94 = "chinastrats.com" nocase
        $domain95 = "chirrups-download.ml" nocase
        $domain96 = "chit-chat-e9053-default-rtdb.firebaseio.com" nocase
        $domain97 = "chucknorr.com" nocase
        $domain98 = "cialiseight.info" nocase
        $domain99 = "civihr.org" nocase
        $ip100 = "103.106.2.35"
        $ip101 = "104.27.172.22"
        $ip102 = "104.27.173.22"
        $ip103 = "106.215.68.174"
        $ip104 = "108.62.12.210"
        $ip105 = "142.202.191.234"
        $ip106 = "142.234.157.195"
        $ip107 = "142.234.157.195"
        $ip108 = "146.70.79.15"
        $ip109 = "162.216.240.173"
        $ip110 = "172.67.180.160"
        $ip111 = "172.81.62.199"
        $ip112 = "172.81.62.199"
        $ip113 = "172.81.62.199"
        $ip114 = "172.94.99.215"
        $ip115 = "176.56.237.126"
        $ip116 = "185.157.78.135"
        $ip117 = "185.193.38.24"
        $ip118 = "185.29.10.117"
        $ip119 = "185.61.148.223"
        $ip120 = "185.74.222.165"
        $ip121 = "185.74.222.169"
        $ip122 = "185.74.222.233"
        $ip123 = "185.74.222.34"
        $ip124 = "185.82.216.57"
        $ip125 = "188.241.58.60"
        $ip126 = "188.241.58.61"
        $ip127 = "192.250.236.76"
        $ip128 = "194.156.98.121"
        $ip129 = "194.156.98.141"
        $ip130 = "194.156.98.21"
        $ip131 = "194.156.98.51"
        $ip132 = "194.156.99.203"
        $ip133 = "194.156.99.229"
        $ip134 = "194.156.99.239"
        $ip135 = "195.20.54.105"
        $ip136 = "208.91.197.91"
        $ip137 = "23.163.0.133"
        $ip138 = "38.180.95.185"
        $ip139 = "43.241.73.185"
        $ip140 = "45.125.64.219"
        $ip141 = "45.125.67.102"
        $ip142 = "45.125.67.215"
        $ip143 = "45.56.165.100"
        $ip144 = "46.165.249.223"
        $ip145 = "47.92.162.135"
        $ip146 = "5.199.163.51"
        $ip147 = "51.89.251.8"
        $ip148 = "74.119.193.154"
        $ip149 = "74.119.193.246"

    condition:
        any of them
}

rule APT_PEEPINGTITLE {
    meta:
        description = "Indicators associated with APT PEEPINGTITLE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "magalenha"

    strings:
        $ip0 = "81.200.152.38"

    condition:
        any of them
}

rule APT_PEGASUS {
    meta:
        description = "Indicators associated with APT PEGASUS"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "123tramites.com" nocase
        $domain1 = "14-tracking.com" nocase
        $domain2 = "1minto-start.com" nocase
        $domain3 = "1place-togo.com" nocase
        $domain4 = "24-7clinic.com" nocase
        $domain5 = "301-redirecting.com" nocase
        $domain6 = "365redirect.co" nocase
        $domain7 = "3driving.com" nocase
        $domain8 = "456h612i458g.com" nocase
        $domain9 = "7style.org" nocase
        $domain10 = "800health.net" nocase
        $domain11 = "911hig11carcay959454.com" nocase
        $domain12 = "9jp1dx8odjw1kbkt.f15fwd322.regularhours.net" nocase
        $domain13 = "a-redirect.com" nocase
        $domain14 = "a-resolver.com" nocase
        $domain15 = "aalaan.tv" nocase
        $domain16 = "accomodation-tastes.net" nocase
        $domain17 = "accountant-audio.com" nocase
        $domain18 = "accountcanceled.com" nocase
        $domain19 = "accountnotify.com" nocase
        $domain20 = "accounts-unread.com" nocase
        $domain21 = "accounts.mx" nocase
        $domain22 = "accountsections.com" nocase
        $domain23 = "accountsecurities.org" nocase
        $domain24 = "activate-discount.com" nocase
        $domain25 = "active-folders.com" nocase
        $domain26 = "actorsshop.net" nocase
        $domain27 = "actu24.online" nocase
        $domain28 = "ad-generator.net" nocase
        $domain29 = "ad-switcher.com" nocase
        $domain30 = "add-client.com" nocase
        $domain31 = "additional-costs.com" nocase
        $domain32 = "addmyid.net" nocase
        $domain33 = "addresstimeframe.com" nocase
        $domain34 = "adeal4u.co" nocase
        $domain35 = "adjust-local-settings.co" nocase
        $domain36 = "adjust-local-settings.com" nocase
        $domain37 = "adjustlocalsettings.net" nocase
        $domain38 = "adscreator.net" nocase
        $domain39 = "adsload.co" nocase
        $domain40 = "adsmetrics.co" nocase
        $domain41 = "advert-time.com" nocase
        $domain42 = "advert-track.com" nocase
        $domain43 = "afriquenouvelle.com" nocase
        $domain44 = "afternicweb.net" nocase
        $domain45 = "agilityprocessing.net" nocase
        $domain46 = "aircraftsxhibition.com" nocase
        $domain47 = "ajelnews.net" nocase
        $domain48 = "akhbar-aliqtisad.com" nocase
        $domain49 = "akhbar-almasdar.com" nocase
        $domain50 = "akhbar-arabia.com" nocase
        $domain51 = "akhbar-islamyah.com" nocase
        $domain52 = "akhbara-aalawsat.com" nocase
        $domain53 = "akhbarnew.com" nocase
        $domain54 = "al-nusr.net" nocase
        $domain55 = "al-taleanews.net" nocase
        $domain56 = "al-taleanewsonline.net" nocase
        $domain57 = "al7erak247.com" nocase
        $domain58 = "al7eraknews.com" nocase
        $domain59 = "alawaeltech.com" nocase
        $domain60 = "albumphotopro.biz" nocase
        $domain61 = "alignmentdisabled.net" nocase
        $domain62 = "alive2plunge.com" nocase
        $domain63 = "all-sales.info" nocase
        $domain64 = "allaboutwrightwood.com" nocase
        $domain65 = "allafricaninfo.com" nocase
        $domain66 = "allbeautifularts.com" nocase
        $domain67 = "alldaycooking.co" nocase
        $domain68 = "allergiesandcooking.com" nocase
        $domain69 = "allfadiha.co" nocase
        $domain70 = "alljazeera.co" nocase
        $domain71 = "allladiesloveme.com" nocase
        $domain72 = "allthecolorsyoulike.com" nocase
        $domain73 = "allthegamesyouneed.com" nocase
        $domain74 = "allthemakeupyouneed.com" nocase
        $domain75 = "allthesongsyoulike.com" nocase
        $domain76 = "alluneed4home.net" nocase
        $domain77 = "alpharythme.com" nocase
        $domain78 = "alrainew.com" nocase
        $domain79 = "android-core.org" nocase
        $domain80 = "android-updates.net" nocase
        $domain81 = "animal-politico.com" nocase
        $domain82 = "api.priveetalk.com" nocase
        $domain83 = "apiapple.com" nocase
        $domain84 = "apigraphs.net" nocase
        $domain85 = "apiwacdn.com" nocase
        $domain86 = "appleleaveit.co" nocase
        $domain87 = "applicationcreation.net" nocase
        $domain88 = "appointments-online.com" nocase
        $domain89 = "appsgratis.com.mx" nocase
        $domain90 = "appsjuegos.com.mx" nocase
        $domain91 = "ar-tweets.com" nocase
        $domain92 = "arab-share.com" nocase
        $domain93 = "arabia-islamion.com" nocase
        $domain94 = "arabnews365.com" nocase
        $domain95 = "arabworld.biz" nocase
        $domain96 = "arabworldnews.info" nocase
        $domain97 = "around-theglobe.co" nocase
        $domain98 = "arrowowner.com" nocase
        $domain99 = "asrararabiya.co" nocase

    condition:
        any of them
}

rule APT_PITTYTIGER {
    meta:
        description = "Indicators associated with APT PITTYTIGER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt5, apt-5, pittypanda"

    strings:
        $domain0 = "acers.com.tw" nocase
        $domain1 = "avstore.com.tw" nocase
        $domain2 = "dopodo.com.tw" nocase
        $domain3 = "foxcom.com.tw" nocase
        $domain4 = "helosaf.com.tw" nocase
        $domain5 = "killerhost.skypetm.com.tw" nocase
        $domain6 = "kimoo.com.tw" nocase
        $domain7 = "lightening.com.tw" nocase
        $domain8 = "newb02.skypetm.com.tw" nocase
        $domain9 = "paccfic.com" nocase
        $domain10 = "seed01.com.tw" nocase
        $domain11 = "skypetm.com.tw" nocase
        $domain12 = "stareastnet.com.tw" nocase
        $domain13 = "symantecs.com.tw" nocase
        $domain14 = "trendmicro.org.tw" nocase
        $domain15 = "trendmicroup.com" nocase

    condition:
        any of them
}

rule APT_PKPLUG {
    meta:
        description = "Indicators associated with APT PKPLUG"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "3w.tcpdo.net" nocase
        $domain1 = "admin.nslookupdns.com" nocase
        $domain2 = "adminloader.com" nocase
        $domain3 = "adminsysteminfo.com" nocase
        $domain4 = "andphocen.com" nocase
        $domain5 = "app.newfacebk.com" nocase
        $domain6 = "appupdatemoremagic.com" nocase
        $domain7 = "cdncool.com" nocase
        $domain8 = "csip6.biz" nocase
        $domain9 = "dns.cdncool.com" nocase
        $domain10 = "feed-5613.coderformylife.info" nocase
        $domain11 = "gooledriveservice.com" nocase
        $domain12 = "honor2020.ga" nocase
        $domain13 = "hwmt10.w3.ezua.com" nocase
        $domain14 = "imw100pass.imwork.net" nocase
        $domain15 = "info.adminsysteminfo.com" nocase
        $domain16 = "jackhex.md5c.com" nocase
        $domain17 = "jackhex.md5c.net" nocase
        $domain18 = "lala513.gicp.net" nocase
        $domain19 = "linkdatax.com" nocase
        $domain20 = "logitechwkgame.com" nocase
        $domain21 = "lzsps.ml" nocase
        $domain22 = "mail.queryurl.com" nocase
        $domain23 = "md.sony36.com" nocase
        $domain24 = "md5c.net" nocase
        $domain25 = "microsoftdefence.com" nocase
        $domain26 = "microsoftserve.com" nocase
        $domain27 = "mxdnsv6.com" nocase
        $domain28 = "netvovo.windowsnetwork.org" nocase
        $domain29 = "newfacebk.com" nocase
        $domain30 = "news.tibetgroupworks.com" nocase
        $domain31 = "nslookupdns.com" nocase
        $domain32 = "outhmail.com" nocase
        $domain33 = "ppt.bodologetee.com" nocase
        $domain34 = "queryurl.com" nocase
        $domain35 = "re.queryurl.com" nocase
        $domain36 = "sm.umtt.com" nocase
        $domain37 = "sony36.com" nocase
        $domain38 = "tcpdo.net" nocase
        $domain39 = "tibetgroupworks.com" nocase
        $domain40 = "up.outhmail.com" nocase
        $domain41 = "update.newfacebk.com" nocase
        $domain42 = "update.queryurl.com" nocase
        $domain43 = "update.tcpdo.net" nocase
        $domain44 = "uvfr43p.com" nocase
        $domain45 = "uvfr4ep.com" nocase
        $domain46 = "uyghurapps.net" nocase
        $domain47 = "w3.changeip.org" nocase
        $domain48 = "w3.ezua.com" nocase
        $domain49 = "web.microsoftdefence.com" nocase
        $domain50 = "web.outlooksysm.net" nocase
        $domain51 = "webserver.servehttp.com" nocase
        $domain52 = "windowsnetwork.org" nocase
        $domain53 = "work.andphocen.com" nocase
        $domain54 = "workwifi.andphocen.com" nocase
        $domain55 = "www3.mefound.com" nocase
        $domain56 = "www5.zyns.com" nocase
        $domain57 = "yl.andphocen.com" nocase

    condition:
        any of them
}

rule APT_PLATINUM {
    meta:
        description = "Indicators associated with APT PLATINUM"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "happiness.freevar.com" nocase

    condition:
        any of them
}

rule APT_POKINGTHEBEAR {
    meta:
        description = "Indicators associated with APT POKINGTHEBEAR"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "RedControle, StickyKeys"

    strings:
        $domain0 = "10-sendmail.ru" nocase
        $domain1 = "3-sendmail.ru" nocase
        $domain2 = "a-nhk.ru" nocase
        $domain3 = "agrarnik-ooo.ru" nocase
        $domain4 = "agrocentrer-eurohem.ru" nocase
        $domain5 = "agroudo.ru" nocase
        $domain6 = "amonni.ru" nocase
        $domain7 = "audemar-piguet.ru" nocase
        $domain8 = "autch-mail.ru" nocase
        $domain9 = "azot-n.ru" nocase
        $domain10 = "azot-sds.ru" nocase
        $domain11 = "azotsds.ru" nocase
        $domain12 = "azs-gazpromneft.ru" nocase
        $domain13 = "balecsm.ru" nocase
        $domain14 = "barsintez.ru" nocase
        $domain15 = "bashneft-centralasia.ru" nocase
        $domain16 = "bashneft.su" nocase
        $domain17 = "berkovetc.ru" nocase
        $domain18 = "bitmain.org.ru" nocase
        $domain19 = "bitum-gazpromneft.ru" nocase
        $domain20 = "bitum-rosneft.ru" nocase
        $domain21 = "bitum-samara.ru" nocase
        $domain22 = "bitumnpk.ru" nocase
        $domain23 = "bor-silicat.ru" nocase
        $domain24 = "box5.photosfromcessna.com" nocase
        $domain25 = "bulgarsyntezi.ru" nocase
        $domain26 = "bunker-rosneft.ru" nocase
        $domain27 = "card-rn.ru" nocase
        $domain28 = "center-nic.ru" nocase
        $domain29 = "chem-torg.ru" nocase
        $domain30 = "chemcourier.ru" nocase
        $domain31 = "chickenpaws.ru" nocase
        $domain32 = "china-technika.ru" nocase
        $domain33 = "combisapsan.ru" nocase
        $domain34 = "contacts.rosneft-opt.su" nocase
        $domain35 = "cryptoman.org.ru" nocase
        $domain36 = "dc-02ec0b5f-mail.mail-autch.ru" nocase
        $domain37 = "dc-0649e3d7-mail.mp-star.ru" nocase
        $domain38 = "dc-45e81045-mail.cibur.ru" nocase
        $domain39 = "dc-99de0f72f24b.3-sendmail.ru" nocase
        $domain40 = "dv-china.ru" nocase
        $domain41 = "electronrg.ru" nocase
        $domain42 = "euro-bitum.ru" nocase
        $domain43 = "euro-chimgroup.ru" nocase
        $domain44 = "eurochem-nevinnomissk.ru" nocase
        $domain45 = "eurochem-novomoskovsk.ru" nocase
        $domain46 = "eurochem-orel.ru" nocase
        $domain47 = "eurochem-trading.com" nocase
        $domain48 = "eurochem-trading.ru" nocase
        $domain49 = "eurochemnovomoskovsk.ru" nocase
        $domain50 = "eurohem-novomokcovsk.ru" nocase
        $domain51 = "eurohem.ru" nocase
        $domain52 = "eurohemgroup.ru" nocase
        $domain53 = "exp.gazpromlpj.ru" nocase
        $domain54 = "expert-cabel.ru" nocase
        $domain55 = "farr-post.ru" nocase
        $domain56 = "fesagro.ru" nocase
        $domain57 = "flatglas.ru" nocase
        $domain58 = "frigat-m.ru" nocase
        $domain59 = "g-pntrade.ru" nocase
        $domain60 = "gazprom-bitumen.ru" nocase
        $domain61 = "gazprom-centralasia.ru" nocase
        $domain62 = "gazprom-international.su" nocase
        $domain63 = "gazpromlpg.com" nocase
        $domain64 = "gazpromlpj.ru" nocase
        $domain65 = "gazpromlpq.ru" nocase
        $domain66 = "gazpromneft-aero.ru" nocase
        $domain67 = "gispnd.ru" nocase
        $domain68 = "gpn-salavat.ru" nocase
        $domain69 = "hcsds-azot.ru" nocase
        $domain70 = "imap.mrggazprom.ru" nocase
        $domain71 = "inter-finans.ru" nocase
        $domain72 = "inter-lens.ru" nocase
        $domain73 = "john-dir.ru" nocase
        $domain74 = "kartll.ru" nocase
        $domain75 = "kolomna-profil.ru" nocase
        $domain76 = "kub-oil.ru" nocase
        $domain77 = "kuban-phosagro.ru" nocase
        $domain78 = "kubeliai.lt" nocase
        $domain79 = "kubmaslozavod.ru" nocase
        $domain80 = "kyrgyzstan-gazprom.ru" nocase
        $domain81 = "lpggazprom.ru" nocase
        $domain82 = "lubricants-rn.ru" nocase
        $domain83 = "lubricants-rosneft.com" nocase
        $domain84 = "lubricants-rosneft.ru" nocase
        $domain85 = "mag-numoil.ru" nocase
        $domain86 = "mail-autch.ru" nocase
        $domain87 = "map.ros-razvitie.ru" nocase
        $domain88 = "margcom.ru" nocase
        $domain89 = "masterhoste.ru" nocase
        $domain90 = "mazutibitum.ru" nocase
        $domain91 = "mc-gp.ru" nocase
        $domain92 = "mekstekla.ru" nocase
        $domain93 = "mendeleevscazot.ru" nocase
        $domain94 = "mendeleevsk-azot.ru" nocase
        $domain95 = "metalloprakat.ru" nocase
        $domain96 = "mp-star.ru" nocase
        $domain97 = "mpt-o.ru" nocase
        $domain98 = "mrg-gazprom.ru" nocase
        $domain99 = "mrggazprom.ru" nocase
        $ip100 = "83.166.242.15"
        $ip101 = "91.211.245.246"

    condition:
        any of them
}

rule APT_POLONIUM {
    meta:
        description = "Indicators associated with APT POLONIUM"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "146.70.86.6"
        $ip1 = "185.203.119.99"
        $ip2 = "185.244.129.216"
        $ip3 = "185.244.129.216"
        $ip4 = "185.244.129.79"
        $ip5 = "195.166.100.23"
        $ip6 = "45.137.148.7"
        $ip7 = "45.80.148.119"
        $ip8 = "45.80.148.167"
        $ip9 = "45.80.148.167"
        $ip10 = "45.80.148.186"
        $ip11 = "45.80.149.108"
        $ip12 = "45.80.149.154"
        $ip13 = "45.80.149.154"
        $ip14 = "45.80.149.22"
        $ip15 = "45.80.149.68"

    condition:
        any of them
}

rule APT_POTAO {
    meta:
        description = "Indicators associated with APT POTAO"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "camprainbowgold.ru" nocase
        $domain1 = "mntexpress.com" nocase
        $domain2 = "poolwaterslide2011.ru" nocase
        $domain3 = "truecryptrussia.ru" nocase
        $domain4 = "worldairpost.com" nocase
        $domain5 = "worldairpost.net" nocase

    condition:
        any of them
}

rule APT_PREDATOR {
    meta:
        description = "Indicators associated with APT PREDATOR"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "CVE-2023-41991, CVE-2023-41992, CVE-2023-41993"

    strings:
        $domain0 = "1domainregistry.com" nocase
        $domain1 = "almal-news.com" nocase
        $domain2 = "asistentcomercialonline.com" nocase
        $domain3 = "barbequebros.com" nocase
        $domain4 = "beinfo.net" nocase
        $domain5 = "bestshowineu.com" nocase
        $domain6 = "betly.me" nocase
        $domain7 = "blocoinformativo.com" nocase
        $domain8 = "bni-madagascar.com" nocase
        $domain9 = "boundbreeze.com" nocase
        $domain10 = "branchbreeze.com" nocase
        $domain11 = "buysalesblog.com" nocase
        $domain12 = "c.betly.me" nocase
        $domain13 = "c1tvapp.com" nocase
        $domain14 = "c3p0solutions.com" nocase
        $domain15 = "cabinet-salyk.kz" nocase
        $domain16 = "caddylane.com" nocase
        $domain17 = "canylane.com" nocase
        $domain18 = "chat-support.support" nocase
        $domain19 = "cheesyarcade.com" nocase
        $domain20 = "cibeg.online" nocase
        $domain21 = "clockpatcher.com" nocase
        $domain22 = "colabfile.com" nocase
        $domain23 = "craftilly.com" nocase
        $domain24 = "despachosnegocios.com" nocase
        $domain25 = "dollgoodies.com" nocase
        $domain26 = "drivemountain.com" nocase
        $domain27 = "e-kgd.kz" nocase
        $domain28 = "eclipsemonitor.com" nocase
        $domain29 = "eppointment.io" nocase
        $domain30 = "eroticsmoments.com" nocase
        $domain31 = "espeednet.com" nocase
        $domain32 = "flickerxxx.com" nocase
        $domain33 = "fr-monde.com" nocase
        $domain34 = "fruitynew.com" nocase
        $domain35 = "g.sec-flare.com" nocase
        $domain36 = "gameformovies.com" nocase
        $domain37 = "gamestuts.com" nocase
        $domain38 = "gardalul.com" nocase
        $domain39 = "gettravelright.com" nocase
        $domain40 = "gilfonts.com" nocase
        $domain41 = "gobbledgums.com" nocase
        $domain42 = "happytotstoys.com" nocase
        $domain43 = "healthyhub.io" nocase
        $domain44 = "holidaypriceguide.com" nocase
        $domain45 = "humansprinter.com" nocase
        $domain46 = "infoaomomento.com" nocase
        $domain47 = "infoshoutout.com" nocase
        $domain48 = "jumia-egy.com" nocase
        $domain49 = "keep-badinigroups.com" nocase
        $domain50 = "kejoranews.net" nocase
        $domain51 = "lawrdo.com" nocase
        $domain52 = "lesautreseux.com" nocase
        $domain53 = "locmap.org" nocase
        $domain54 = "longtester.com" nocase
        $domain55 = "mappins.io" nocase
        $domain56 = "mapsloc.net" nocase
        $domain57 = "masoloyakati.com" nocase
        $domain58 = "mdundobeats.com" nocase
        $domain59 = "mmegi.co" nocase
        $domain60 = "mountinnovate.com" nocase
        $domain61 = "mundoautopro.com" nocase
        $domain62 = "myfawry.net" nocase
        $domain63 = "myowndrive.net" nocase
        $domain64 = "mypinpoint.org" nocase
        $domain65 = "myprivatedrive.net" nocase
        $domain66 = "myread.io" nocase
        $domain67 = "mystudyup.com" nocase
        $domain68 = "newsfunnel.net" nocase
        $domain69 = "nightskyco.com" nocase
        $domain70 = "noadsview.com" nocase
        $domain71 = "noisyball.com" nocase
        $domain72 = "noticiafamosos.com" nocase
        $domain73 = "noticiafresca.net" nocase
        $domain74 = "notifications-sec.com" nocase
        $domain75 = "notifications.wa-info.com" nocase
        $domain76 = "nuurs.net" nocase
        $domain77 = "nyirangongovrai.com" nocase
        $domain78 = "onelifestyle24.com" nocase
        $domain79 = "openstreetpro.com" nocase
        $domain80 = "pedalmastery.com" nocase
        $domain81 = "pepalaunch-airdrop.info" nocase
        $domain82 = "pinnedplace.com" nocase
        $domain83 = "promobyfit.com" nocase
        $domain84 = "remixspot.com" nocase
        $domain85 = "rhapresentacao.com" nocase
        $domain86 = "roadsidefoodie.com" nocase
        $domain87 = "runconnect.net" nocase
        $domain88 = "sdntribune.co" nocase
        $domain89 = "sec-flare.com" nocase
        $domain90 = "secneed.com" nocase
        $domain91 = "secretspotnow.com" nocase
        $domain92 = "secsafty.com" nocase
        $domain93 = "shopstodrop.com" nocase
        $domain94 = "southchinapost.net" nocase
        $domain95 = "speedbrawse.com" nocase
        $domain96 = "stableconnect.net" nocase
        $domain97 = "starryedge.com" nocase
        $domain98 = "statuepops.com" nocase
        $domain99 = "steepmatch.com" nocase

    condition:
        any of them
}

rule APT_PUNISHINGOWL {
    meta:
        description = "Indicators associated with APT PUNISHINGOWL"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "acquerifec.com" nocase
        $domain1 = "ayobabelan.com" nocase
        $domain2 = "b0aweb0.refec.site" nocase
        $domain3 = "bloggoversikten.com" nocase
        $domain4 = "outlook-d12.zyns.com" nocase
        $domain5 = "refec.site" nocase
        $domain6 = "refreb0.com" nocase
        $domain7 = "refreb1.info" nocase
        $domain8 = "ws.iferc.com" nocase
        $ip9 = "82.221.100.40"
        $ip10 = "95.174.65.218"

    condition:
        any of them
}

rule APT_PURPLEHAZE {
    meta:
        description = "Indicators associated with APT PURPLEHAZE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "goreshell"

    strings:
        $domain0 = "ccna.organiccrap.com" nocase
        $domain1 = "cloud.trendav.co" nocase
        $domain2 = "downloads.trendav.vip" nocase
        $domain3 = "epp.navy.ddns.info" nocase
        $domain4 = "mail.ccna.organiccrap.com" nocase
        $domain5 = "mail.secmailbox.us" nocase
        $domain6 = "navy.ddns.info" nocase
        $domain7 = "secmailbox.us" nocase
        $domain8 = "sentinelxdr.us" nocase
        $domain9 = "tatacom.duckdns.org" nocase
        $domain10 = "trendav.vip" nocase
        $ip11 = "45.13.199.209"

    condition:
        any of them
}

rule APT_PUTTERPANDA {
    meta:
        description = "Indicators associated with APT PUTTERPANDA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "msupdater"

    strings:
        $domain0 = "great.vssigma.com" nocase
        $domain1 = "red.vssigma.com" nocase
        $domain2 = "resell.siseau.com" nocase
        $domain3 = "siseau.com" nocase
        $domain4 = "vssigma.com" nocase

    condition:
        any of them
}

rule APT_Q015 {
    meta:
        description = "Indicators associated with APT Q015"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "utg-q-015, operation run"

    strings:
        $domain0 = "beta.naipump.xyz" nocase
        $domain1 = "biodao.finance" nocase
        $domain2 = "chormeupdatetool.xyz" nocase
        $domain3 = "molecular-mazda-forests-shop.trycloudflare.com" nocase
        $domain4 = "naipump.xyz" nocase
        $domain5 = "safe-controls.oss-cn-hongkong.aliyuncs.com" nocase
        $domain6 = "updategoogls.cc" nocase
        $ip7 = "194.34.254.219"
        $ip8 = "194.34.254.219"
        $ip9 = "209.250.254.130"
        $ip10 = "209.250.254.130"
        $ip11 = "209.250.254.130"

    condition:
        any of them
}

rule APT_Q12 {
    meta:
        description = "Indicators associated with APT Q12"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "aufreighttransport.com" nocase
        $domain1 = "controlmytraffic.com" nocase
        $domain2 = "coredashcloud.com" nocase
        $domain3 = "guesttrafficinformation.com" nocase
        $domain4 = "hoaquincloud.com" nocase
        $domain5 = "msvsseccloud.com" nocase
        $domain6 = "nyculturecloud.com" nocase
        $domain7 = "org-nk.com" nocase
        $domain8 = "tomatozcloud.com" nocase
        $domain9 = "trafficcheckdaily.com" nocase
        $ip10 = "185.181.229.110"
        $ip11 = "185.181.230.110"
        $ip12 = "185.181.230.71"
        $ip13 = "185.231.222.86"
        $ip14 = "192.236.209.139"
        $ip15 = "23.81.42.154"
        $ip16 = "46.183.27.134"
        $ip17 = "51.77.72.146"

    condition:
        any of them
}

rule APT_Q27 {
    meta:
        description = "Indicators associated with APT Q27"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-q-27, dragon breath, golden eye dog"

    strings:
        $domain0 = "123.nsjdhmdjs.com" nocase
        $domain1 = "2.nsjdhmdjs.com" nocase
        $domain2 = "2.potatouu.com" nocase
        $domain3 = "a.pic447.com" nocase
        $domain4 = "ac2.nsjdhmdjs.com" nocase
        $domain5 = "api.keensie.com" nocase
        $domain6 = "d.pic447.com" nocase
        $domain7 = "datareportnew.s3.ap-northeast-2.amazonaws.com" nocase
        $domain8 = "goldeyeuu.io" nocase
        $domain9 = "l.pic447.com" nocase
        $domain10 = "l2.pic447.com" nocase
        $domain11 = "links3s.s3.ap-east-1.amazonaws.com" nocase
        $domain12 = "nsjdhmdjs.com" nocase
        $domain13 = "potatouu.com" nocase
        $domain14 = "s3work08.s3.ap-east-1.amazonaws.com" nocase
        $domain15 = "t.pic447.com" nocase
        $domain16 = "uu.goldeyeuu.io" nocase
        $domain17 = "v.pic447.com" nocase
        $domain18 = "v2.pic447.com" nocase
        $domain19 = "w.pic447.com" nocase
        $domain20 = "wk.goldeyeuu.io" nocase
        $domain21 = "yy-service.s3.ap-northeast-2.amazonaws.com" nocase
        $domain22 = "yyupdats.s3.ap-southeast-1.amazonaws.com" nocase
        $ip23 = "143.92.57.46"
        $ip24 = "185.135.79.196"
        $ip25 = "185.135.79.200"
        $ip26 = "206.233.128.103"
        $ip27 = "35.78.126.246"

    condition:
        any of them
}

rule APT_QUARIAN {
    meta:
        description = "Indicators associated with APT QUARIAN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "BackdoorDiplomacy, Quarian, Turian"

    strings:
        $domain0 = "250f7cloud.crmdev.org" nocase
        $domain1 = "29c04uc.ejalase.org" nocase
        $domain2 = "62ffauc.ejalase.org" nocase
        $domain3 = "7f4d9fcanet.microsoftshop.org" nocase
        $domain4 = "adboeonline.net" nocase
        $domain5 = "alberto2011.com" nocase
        $domain6 = "andyothers.acmetoy.com" nocase
        $domain7 = "bill.microsoftbuys.com" nocase
        $domain8 = "buffetfactory.oicp.io" nocase
        $domain9 = "cloud.fastpaymentser-vice.com" nocase
        $domain10 = "cloud.microsoftshop.org" nocase
        $domain11 = "cloud.skypecloud.net" nocase
        $domain12 = "crmdev.org" nocase
        $domain13 = "delldrivers.in" nocase
        $domain14 = "dnsupdate.dns1.us" nocase
        $domain15 = "dnsupdate.dns2.us" nocase
        $domain16 = "dynsystem.imbbs.in" nocase
        $domain17 = "efanshion.com" nocase
        $domain18 = "ejalase.org" nocase
        $domain19 = "fastpaymentser-vice.com" nocase
        $domain20 = "fazlol-lah.net" nocase
        $domain21 = "fazlollah.net" nocase
        $domain22 = "freedns02.dns2.us" nocase
        $domain23 = "icta.worldmessg.com" nocase
        $domain24 = "info.fazlol-lah.net" nocase
        $domain25 = "info.fazlollah.net" nocase
        $domain26 = "info.payamra-dio.com" nocase
        $domain27 = "info.payamradio.com" nocase
        $domain28 = "intelupdate.dns1.us" nocase
        $domain29 = "irir.org" nocase
        $domain30 = "keep.ns3.name" nocase
        $domain31 = "mail.irir.org" nocase
        $domain32 = "mci.ejalase.org" nocase
        $domain33 = "mfaantivirus.xyz" nocase
        $domain34 = "microsoftbuys.com" nocase
        $domain35 = "microsoftshop.org" nocase
        $domain36 = "news.alberto2011.com" nocase
        $domain37 = "officenews365.com" nocase
        $domain38 = "officeupdate.ns01.us" nocase
        $domain39 = "officeupdates.cleansite.us" nocase
        $domain40 = "oracleapps.org" nocase
        $domain41 = "payamra-dio.com" nocase
        $domain42 = "payamradio.com" nocase
        $domain43 = "pfs1010.com" nocase
        $domain44 = "pfs1010.xyz" nocase
        $domain45 = "picture.efanshion.com" nocase
        $domain46 = "plastic.delldrivers.in" nocase
        $domain47 = "pmdskm.top" nocase
        $domain48 = "proxy.oracleapps.org" nocase
        $domain49 = "scm.oracleapps.org" nocase
        $domain50 = "skypecloud.net" nocase
        $domain51 = "srv.fazlollah.net" nocase
        $domain52 = "srv.payamradio.com" nocase
        $domain53 = "support.vpnkerio.com" nocase
        $domain54 = "systeminfo.cleansite.info" nocase
        $domain55 = "systeminfo.myftp.name" nocase
        $domain56 = "systeminfo.oicp.net" nocase
        $domain57 = "szsz.pmdskm.top" nocase
        $domain58 = "uc.ejalase.org" nocase
        $domain59 = "update.adboeonline.net" nocase
        $domain60 = "update.delldrivers.in" nocase
        $domain61 = "update.officenews365.com" nocase
        $domain62 = "updateip.onmypc.net" nocase
        $domain63 = "vpnkerio.com" nocase
        $domain64 = "web.vpnkerio.com" nocase
        $domain65 = "winupdate.ns02.us" nocase
        $domain66 = "worldmessg.com" nocase

    condition:
        any of them
}

rule APT_QUASAR {
    meta:
        description = "Indicators associated with APT QUASAR"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bandtester.com" nocase
        $domain1 = "datasamsung.com" nocase
        $domain2 = "down.downloadoneyoutube.co.vu" nocase
        $domain3 = "downloadlog.linkpc.net" nocase
        $domain4 = "downloadmyhost.zapto.org" nocase
        $domain5 = "downloadtesting.com" nocase
        $domain6 = "dynamicipaddress.linkpc.net" nocase
        $domain7 = "exportball.servegame.org" nocase
        $domain8 = "ftpserverit.otzo.com" nocase
        $domain9 = "galaxy-s.com" nocase
        $domain10 = "galaxysupdates.com" nocase
        $domain11 = "gameoolines.com" nocase
        $domain12 = "gamestoplay.bid" nocase
        $domain13 = "havan.qhigh.com" nocase
        $domain14 = "help2014.linkpc.net" nocase
        $domain15 = "helpyoume.linkpc.net" nocase
        $domain16 = "hostgatero.ddns.net" nocase
        $domain17 = "kolabdown.sytes.net" nocase
        $domain18 = "microsoftnewupdate.com" nocase
        $domain19 = "netstreamag.publicvm.com" nocase
        $domain20 = "newphoneapp.com" nocase
        $domain21 = "noredirecto.redirectme.net" nocase
        $domain22 = "onlinesoft.space" nocase
        $domain23 = "progsupdate.com" nocase
        $domain24 = "rotter2.publicvm.com" nocase
        $domain25 = "safara.sytes.net" nocase
        $domain26 = "smartsftp.pw" nocase
        $domain27 = "speedbind.com" nocase
        $domain28 = "subsidiaryohio.linkpc.net" nocase
        $domain29 = "topgamse.com" nocase
        $domain30 = "ukgames.tech" nocase
        $domain31 = "viewnet.better-than.tv" nocase
        $domain32 = "wallanews.publicvm.com" nocase
        $domain33 = "wallanews.sytes.net" nocase
        $domain34 = "webfile.myq-see.com" nocase

    condition:
        any of them
}

rule APT_RAINBOWHYENA {
    meta:
        description = "Indicators associated with APT RAINBOWHYENA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "phantomremote, phantomcore, phantomocx"

    strings:
        $domain0 = "146.190.234.multiversitetet.no" nocase
        $domain1 = "193.37.71.221.sslip.io" nocase
        $domain2 = "1be.pro" nocase
        $domain3 = "1to30.shop" nocase
        $domain4 = "3hito.tech" nocase
        $domain5 = "50forwardspodcast.co.uk" nocase
        $domain6 = "7evenfoundation.org" nocase
        $domain7 = "92108.sbs" nocase
        $domain8 = "aainfo.online" nocase
        $domain9 = "abhinayafoodrecipes.com" nocase
        $domain10 = "abstractcorner.com" nocase
        $domain11 = "account.win-shares.com" nocase
        $domain12 = "acquisizione.net" nocase
        $domain13 = "activehealth01.online" nocase
        $domain14 = "admirationhq.com" nocase
        $domain15 = "aegissecurity.online" nocase
        $domain16 = "affilipost.com" nocase
        $domain17 = "affordablecarsonline.com" nocase
        $domain18 = "agelessbonds.com" nocase
        $domain19 = "aifix.space" nocase
        $domain20 = "ainghain.com" nocase
        $domain21 = "aiupworkpro.com" nocase
        $domain22 = "alliedambitions.com" nocase
        $domain23 = "allin1livetv.xyz" nocase
        $domain24 = "allretail.shop" nocase
        $domain25 = "allstaramerican.com" nocase
        $domain26 = "almaxhura.com" nocase
        $domain27 = "alquilerdecuatrimotosmedellin.com" nocase
        $domain28 = "alsawsanaalsawdaa.com" nocase
        $domain29 = "alugueseusite.net" nocase
        $domain30 = "alvarezgabriel.com" nocase
        $domain31 = "alyseikari.com" nocase
        $domain32 = "ama30anos.online" nocase
        $domain33 = "amaatucachorro.com" nocase
        $domain34 = "americancrepes.co" nocase
        $domain35 = "amritsariyadhaba.com" nocase
        $domain36 = "analytisec.space" nocase
        $domain37 = "andrescardenas.uno" nocase
        $domain38 = "anishpitale.com" nocase
        $domain39 = "antenasbet.online" nocase
        $domain40 = "anthonychukwu.net" nocase
        $domain41 = "aonemy.com" nocase
        $domain42 = "app.shieldify.online" nocase
        $domain43 = "appeasy.ai" nocase
        $domain44 = "appulse.info" nocase
        $domain45 = "areamarket.online" nocase
        $domain46 = "arkadcorretora.online" nocase
        $domain47 = "artmateriali.com" nocase
        $domain48 = "arya-anggara.xyz" nocase
        $domain49 = "ashariyya.online" nocase
        $domain50 = "astralmetaverse.com" nocase
        $domain51 = "ataevisinop.com" nocase
        $domain52 = "atelier-bever.com" nocase
        $domain53 = "atendimentohumanasaude.online" nocase
        $domain54 = "atomms.cloud" nocase
        $domain55 = "aura-entdecken.com" nocase
        $domain56 = "bbcars.shop" nocase
        $domain57 = "beezai.fun" nocase
        $domain58 = "bellebindi.com" nocase
        $domain59 = "bestanews.com" nocase
        $domain60 = "bignewsblog.com" nocase
        $domain61 = "billionairejewels.shop" nocase
        $domain62 = "bindrehab.org" nocase
        $domain63 = "binramdoun.com" nocase
        $domain64 = "bloomvaults.com" nocase
        $domain65 = "bluecollarseoexperts.com" nocase
        $domain66 = "bodyandenergy.shop" nocase
        $domain67 = "borboletacriativarecursos.online" nocase
        $domain68 = "botiicario.com" nocase
        $domain69 = "brandiqueindonesia.com" nocase
        $domain70 = "bravebrandcircle.com" nocase
        $domain71 = "brightshield.space" nocase
        $domain72 = "brokerclash.com" nocase
        $domain73 = "brookhvrst.com" nocase
        $domain74 = "buildaround.org" nocase
        $domain75 = "bundlemeister.com" nocase
        $domain76 = "bxmarmiton.com" nocase
        $domain77 = "cafefiladelfia.com" nocase
        $domain78 = "callbucdial.store" nocase
        $domain79 = "camilasobrino.com" nocase
        $domain80 = "cartaopg.bet" nocase
        $domain81 = "casasantosltda.shop" nocase
        $domain82 = "castlecyberskull.fun" nocase
        $domain83 = "ccis-progeco.com" nocase
        $domain84 = "ceostorymagazine.com" nocase
        $domain85 = "chandrikaproperties4you.co.uk" nocase
        $domain86 = "charlsmontero.com" nocase
        $domain87 = "charmingfrenchhouse.com" nocase
        $domain88 = "chickengrill.store" nocase
        $domain89 = "childpsychologyai.com" nocase
        $domain90 = "cifzap.online" nocase
        $domain91 = "cityscaperent.com" nocase
        $domain92 = "clareadordemanchas.store" nocase
        $domain93 = "clickmoney.online" nocase
        $domain94 = "clientsatisfy.com" nocase
        $domain95 = "cloudinor.com" nocase
        $domain96 = "cloudtips.shop" nocase
        $domain97 = "coinova.online" nocase
        $domain98 = "collagenjelly.store" nocase
        $domain99 = "comcast-technology.com" nocase
        $ip100 = "178.255.127.65"
        $ip101 = "185.80.91.107"
        $ip102 = "193.176.153.162"
        $ip103 = "193.176.153.162"
        $ip104 = "195.133.32.213"
        $ip105 = "213.232.204.111"
        $ip106 = "213.232.204.111"
        $ip107 = "31.56.227.100"
        $ip108 = "31.56.227.100"
        $ip109 = "31.56.227.100"
        $ip110 = "31.56.227.61"
        $ip111 = "31.56.227.61"
        $ip112 = "31.56.227.61"
        $ip113 = "31.56.227.61"
        $ip114 = "31.56.227.61"
        $ip115 = "31.56.227.61"
        $ip116 = "31.56.227.61"
        $ip117 = "31.56.227.61"
        $ip118 = "31.56.48.178"
        $ip119 = "31.58.137.197"
        $ip120 = "31.58.137.197"
        $ip121 = "31.58.137.197"
        $ip122 = "45.11.27.232"
        $ip123 = "45.87.245.30"
        $ip124 = "45.87.246.169"
        $ip125 = "5.252.176.77"
        $ip126 = "5.252.176.77"
        $ip127 = "80.66.81.13"
        $ip128 = "80.66.81.13"
        $ip129 = "94.183.188.166"
        $ip130 = "94.183.188.166"
        $ip131 = "94.183.188.166"

    condition:
        any of them
}

rule APT_RAMPANTKITTEN {
    meta:
        description = "Indicators associated with APT RAMPANTKITTEN"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "afalr-onedrive.com" nocase
        $domain1 = "afalr-sharepoint.com" nocase
        $domain2 = "alarabiye.net" nocase
        $domain3 = "cpuconfig.com" nocase
        $domain4 = "developerchrome.com" nocase
        $domain5 = "endupload.com" nocase
        $domain6 = "firefox-addons.com" nocase
        $domain7 = "gradleservice.info" nocase
        $domain8 = "mailgoogle.info" nocase
        $domain9 = "picfile.net" nocase
        $domain10 = "telegrambackups.com" nocase
        $domain11 = "telegrambots.me" nocase
        $domain12 = "telegramco.org" nocase
        $domain13 = "telegramdesktop.com" nocase
        $domain14 = "telegramreport.me" nocase
        $domain15 = "telegramup.com" nocase
        $domain16 = "update-help.com" nocase
        $domain17 = "vareangold.de" nocase
        $domain18 = "winchecking.com" nocase

    condition:
        any of them
}

rule APT_RANCOR {
    meta:
        description = "Indicators associated with APT RANCOR"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "754d56-8523.sexidude.com" nocase
        $domain1 = "bafunpda.xyz" nocase
        $domain2 = "charleseedwards.dynamic-dns.net" nocase
        $domain3 = "dsdfdscxcv.justdied.com" nocase
        $domain4 = "dsgsdgergrfv.toythieves.com" nocase
        $domain5 = "facebook-apps.com" nocase
        $domain6 = "ftp.chinhphu.ddns.ms" nocase
        $domain7 = "goole.authorizeddns.us" nocase
        $domain8 = "jdanief.xyz" nocase
        $domain9 = "kfesv.xyz" nocase
        $domain10 = "kibistation.onmypc.net" nocase
        $domain11 = "microsoft.authorizeddns.us" nocase
        $domain12 = "microsoft.https443.org" nocase
        $domain13 = "msdns.otzo.com" nocase
        $domain14 = "nicetiss54.lflink.com" nocase
        $domain15 = "oui6473rf.xxuz.com" nocase
        $domain16 = "sfstnksfcv.jungleheart.com" nocase
        $domain17 = "vvcxvsdvx.dynamic-dns.net" nocase
        $ip18 = "139.162.14.25"

    condition:
        any of them
}

rule APT_REAPER {
    meta:
        description = "Indicators associated with APT REAPER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "account.drive-google-com.tk" nocase
        $domain1 = "account.gommask.online" nocase
        $domain2 = "accounts-youtube.drive-google-com.tk" nocase
        $domain3 = "anyportals.com" nocase
        $domain4 = "cgalim.com" nocase
        $domain5 = "dns-update.club" nocase
        $domain6 = "drive-google-com.tk" nocase
        $domain7 = "gmail.drive-google-com.tk" nocase
        $domain8 = "gommask.online" nocase
        $domain9 = "hakproperty.com" nocase
        $domain10 = "hpserver.online" nocase
        $domain11 = "iblcor.cafe24.com" nocase
        $domain12 = "imagedownloadsupport.com" nocase
        $domain13 = "login.drive-google-com.tk" nocase
        $domain14 = "mailattachmentimageurlxyz.site" nocase
        $domain15 = "mumbai-m.site" nocase
        $domain16 = "pmoae.com" nocase
        $domain17 = "proxycheker.pro" nocase
        $domain18 = "ssl-gstatic.drive-google-com.tk" nocase

    condition:
        any of them
}

rule APT_REDFOXTROT {
    meta:
        description = "Indicators associated with APT REDFOXTROT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "adobesupport.net" nocase
        $domain1 = "adtl.mywire.org" nocase
        $domain2 = "anywheres.run.place" nocase
        $domain3 = "appinfo.camdvr.org" nocase
        $domain4 = "appsupport.my-router.de" nocase
        $domain5 = "appupdate.firewall-gateway.de" nocase
        $domain6 = "appupdate.my-router.de" nocase
        $domain7 = "aries.epac.to" nocase
        $domain8 = "bbsaili.camdvr.org" nocase
        $domain9 = "billing.epac.to" nocase
        $domain10 = "capture.kozow.com" nocase
        $domain11 = "cheapnews.online" nocase
        $domain12 = "chock.mywire.org" nocase
        $domain13 = "ciscoteam.ignorelist.com" nocase
        $domain14 = "coreldraw.kozow.com" nocase
        $domain15 = "czconnections.ddns.info" nocase
        $domain16 = "darkpapa.chickenkiller.com" nocase
        $domain17 = "dhsg123.jkub.com" nocase
        $domain18 = "drdo.dumb1.com" nocase
        $domain19 = "drdo.mypop3.net" nocase
        $domain20 = "dsgf.chickenkiller.com" nocase
        $domain21 = "elienceso.kozow.com" nocase
        $domain22 = "exat.dnset.com" nocase
        $domain23 = "exat.zyns.com" nocase
        $domain24 = "execserver.giize.com" nocase
        $domain25 = "exujjat.xxuz.com" nocase
        $domain26 = "fashget.theworkpc.com" nocase
        $domain27 = "fivenum.mooo.com" nocase
        $domain28 = "foreverlove.zzux.com" nocase
        $domain29 = "forum.camdvr.org" nocase
        $domain30 = "ftp.isronrsc.giize.com" nocase
        $domain31 = "fukebutt.zzux.com" nocase
        $domain32 = "googiao.top" nocase
        $domain33 = "googleupdate.myz.info" nocase
        $domain34 = "gov4us.online" nocase
        $domain35 = "gulistan.wikaba.com" nocase
        $domain36 = "hcl.sexidude.com" nocase
        $domain37 = "holyshit.dynamic-dns.net" nocase
        $domain38 = "honoroftajik.dynamic-dns.net" nocase
        $domain39 = "hostmail1.com" nocase
        $domain40 = "https.dnset.com" nocase
        $domain41 = "https.ikwb.com" nocase
        $domain42 = "https.otzo.com" nocase
        $domain43 = "https.vizvaz.com" nocase
        $domain44 = "inbsnl.ddns.info" nocase
        $domain45 = "inbsnl.ddns.ms" nocase
        $domain46 = "indiabs.nl" nocase
        $domain47 = "indiabsnl.com" nocase
        $domain48 = "indiabsnl.in" nocase
        $domain49 = "indiabsnl.net" nocase
        $domain50 = "indiaeducation.mefound.com" nocase
        $domain51 = "indian.mefound.com" nocase
        $domain52 = "indianmail.zyns.com" nocase
        $domain53 = "indiavoice.site" nocase
        $domain54 = "isronrsc.giize.com" nocase
        $domain55 = "isrosdsc.camdvr.org" nocase
        $domain56 = "itsupport.firewall-gateway.net" nocase
        $domain57 = "jiocircle.site" nocase
        $domain58 = "jpgdowngaussip.ddns.info" nocase
        $domain59 = "kastygost.compress.to" nocase
        $domain60 = "kazcell.info" nocase
        $domain61 = "kazinfo.net" nocase
        $domain62 = "kaznews.shop" nocase
        $domain63 = "kaztelecom.shop" nocase
        $domain64 = "kelimelerdunyasi.org" nocase
        $domain65 = "koreckaccord01.zzux.com" nocase
        $domain66 = "kz-news.site" nocase
        $domain67 = "laugh.toh.info" nocase
        $domain68 = "lexuz.dns05.com" nocase
        $domain69 = "lexuz.x24hr.com" nocase
        $domain70 = "linkedin.organiccrap.com" nocase
        $domain71 = "locker.camdvr.org" nocase
        $domain72 = "login.kozow.com" nocase
        $domain73 = "logonfaker.longmusic.com" nocase
        $domain74 = "macfee.webredirect.org" nocase
        $domain75 = "macfeesyn.ns01.info" nocase
        $domain76 = "macfeeupdate.ddns.info" nocase
        $domain77 = "mail.indiabsnl.com" nocase
        $domain78 = "mail.indiabsnl.in" nocase
        $domain79 = "mall.mywire.org" nocase
        $domain80 = "manual.gleeze.com" nocase
        $domain81 = "manuals.wikaba.com" nocase
        $domain82 = "menus.giize.com" nocase
        $domain83 = "menus.kozow.com" nocase
        $domain84 = "mfedownload.freetcp.com" nocase
        $domain85 = "mfeupdate.ddns.info" nocase
        $domain86 = "mfeupload.freetcp.com" nocase
        $domain87 = "miche.justdied.com" nocase
        $domain88 = "mobai.moshen.xyz" nocase
        $domain89 = "moshen.xyz" nocase
        $domain90 = "msgsober.xxuz.com" nocase
        $domain91 = "msn.dnsnet.com" nocase
        $domain92 = "ncell.app" nocase
        $domain93 = "newseason.online" nocase
        $domain94 = "newsforname.site" nocase
        $domain95 = "newtelecom.shop" nocase
        $domain96 = "nicodonald.accesscam.org" nocase
        $domain97 = "niteast.strangled.net" nocase
        $domain98 = "notice.theworkpc.com" nocase
        $domain99 = "nproccshow.zyns.com" nocase
        $ip100 = "135.181.243.34"
        $ip101 = "164.132.27.225"
        $ip102 = "192.51.188.47"
        $ip103 = "194.126.202.217"

    condition:
        any of them
}

rule APT_REDJULIETT {
    meta:
        description = "Indicators associated with APT REDJULIETT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "cktime.ooguy.com" nocase
        $domain1 = "cond0r.com" nocase
        $domain2 = "dns361.tk" nocase
        $domain3 = "godblack.cf" nocase
        $domain4 = "javacheck.ooguy.com" nocase
        $domain5 = "javaupdate.giize.com" nocase
        $domain6 = "purple76.com" nocase
        $domain7 = "sofeter.ml" nocase
        $domain8 = "solana.onl" nocase
        $domain9 = "togey.online" nocase
        $domain10 = "yeeyeey.top" nocase

    condition:
        any of them
}

rule APT_REDNOVEMBER {
    meta:
        description = "Indicators associated with APT REDNOVEMBER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "storm-2077, leslieloader"

    strings:
        $domain0 = "aeifile.offiec.us.kg" nocase
        $domain1 = "citrix.offiec.us.kg" nocase
        $domain2 = "cna.offiec.us.kg" nocase
        $domain3 = "download.offiec.us.kg" nocase
        $domain4 = "gp.offiec.us.kg" nocase
        $domain5 = "login.offiec.us.kg" nocase
        $domain6 = "test.offiec.us.kg" nocase
        $domain7 = "vpn.offiec.us.kg" nocase
        $domain8 = "vpn1.offiec.us.kg" nocase

    condition:
        any of them
}

rule APT_REDOCTOBER {
    meta:
        description = "Indicators associated with APT REDOCTOBER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bb-apps-world.com" nocase
        $domain1 = "blackberry-apps-world.com" nocase
        $domain2 = "blackberry-update.com" nocase
        $domain3 = "csrss-check-new.com" nocase
        $domain4 = "csrss-update-new.com" nocase
        $domain5 = "csrss-upgrade-new.com" nocase
        $domain6 = "dailyinfonews.net" nocase
        $domain7 = "dll-host-check.com" nocase
        $domain8 = "dll-host-udate.com" nocase
        $domain9 = "dll-host-update.com" nocase
        $domain10 = "dll-host.com" nocase
        $domain11 = "dllupdate.info" nocase
        $domain12 = "drivers-check.com" nocase
        $domain13 = "drivers-get.com" nocase
        $domain14 = "drivers-update-online.com" nocase
        $domain15 = "genuine-check.com" nocase
        $domain16 = "genuineservicecheck.com" nocase
        $domain17 = "genuineupdate.com" nocase
        $domain18 = "hotinfonews.com" nocase
        $domain19 = "microsoft-msdn.com" nocase
        $domain20 = "microsoftcheck.com" nocase
        $domain21 = "microsoftosupdate.com" nocase
        $domain22 = "mobile-update.com" nocase
        $domain23 = "mobileimho.com" nocase
        $domain24 = "mobileimho.ru" nocase
        $domain25 = "ms-software-check.com" nocase
        $domain26 = "ms-software-genuine.com" nocase
        $domain27 = "ms-software-update.com" nocase
        $domain28 = "msgenuine.net" nocase
        $domain29 = "msinfoonline.org" nocase
        $domain30 = "msonlinecheck.com" nocase
        $domain31 = "msonlineget.com" nocase
        $domain32 = "msonlineupdate.com" nocase
        $domain33 = "new-driver-upgrade.com" nocase
        $domain34 = "nt-windows-check.com" nocase
        $domain35 = "nt-windows-online.com" nocase
        $domain36 = "nt-windows-update.com" nocase
        $domain37 = "os-microsoft-check.com" nocase
        $domain38 = "os-microsoft-update.com" nocase
        $domain39 = "osgenuine.com" nocase
        $domain40 = "security-mobile.com" nocase
        $domain41 = "shellupdate.com" nocase
        $domain42 = "svchost-check.com" nocase
        $domain43 = "svchost-online.com" nocase
        $domain44 = "svchost-update.com" nocase
        $domain45 = "update-genuine.com" nocase
        $domain46 = "win-check-update.com" nocase
        $domain47 = "win-driver-upgrade.com" nocase
        $domain48 = "windows-genuine.com" nocase
        $domain49 = "windowscheckupdate.com" nocase
        $domain50 = "windowsonlineupdate.com" nocase
        $domain51 = "wingenuine.com" nocase
        $domain52 = "wins-driver-check.com" nocase
        $domain53 = "wins-driver-update.com" nocase
        $domain54 = "wins-update.com" nocase
        $domain55 = "winupdateonline.com" nocase
        $domain56 = "winupdateos.com" nocase
        $domain57 = "world-mobile-congress.com" nocase
        $domain58 = "xponlineupdate.com" nocase

    condition:
        any of them
}

rule APT_REDWOLF {
    meta:
        description = "Indicators associated with APT REDWOLF"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "redcurl, redwolf, earthkapre"

    strings:
        $domain0 = "alphastoned.pro" nocase
        $domain1 = "amscloudhost.com" nocase
        $domain2 = "app-ins-001.amscloudhost.com" nocase
        $domain3 = "app-ins-002.amscloudhost.com" nocase
        $domain4 = "app-l01.msftcloud.click" nocase
        $domain5 = "app-l03.msftcloud.click" nocase
        $domain6 = "app-l03.servicehost.click" nocase
        $domain7 = "app-l07.servicehost.click" nocase
        $domain8 = "automatinghrservices.workers.dev" nocase
        $domain9 = "bora.teracloud.jp" nocase
        $domain10 = "buyhighroad.scienceontheweb.net" nocase
        $domain11 = "cdn.wgroadcdn.workers.dev" nocase
        $domain12 = "clever.forcloudnetworks.online" nocase
        $domain13 = "cloud-01.servicehost.click" nocase
        $domain14 = "community.rmobileappdevelopment.workers.dev" nocase
        $domain15 = "ctrl1.sm.advhost.co.uk" nocase
        $domain16 = "cvsend.resumeexpert.cloud" nocase
        $domain17 = "datascience.iotconnectivity.workers.dev" nocase
        $domain18 = "dav.automatinghrservices.workers.dev" nocase
        $domain19 = "dav.cloud-01.servicehost.click" nocase
        $domain20 = "dav.linkedin-cloud-manager.servicehost.click" nocase
        $domain21 = "eap.byethost10.com" nocase
        $domain22 = "earthmart.c1.biz" nocase
        $domain23 = "fiona.forcloudnetworks.online" nocase
        $domain24 = "forcloudnetworks.online" nocase
        $domain25 = "hfn-c-001.cc.msftcloud.click" nocase
        $domain26 = "hwsrv-1048332.hostwindsdns.com" nocase
        $domain27 = "ksg-c-001.cc.msftcloud.click" nocase
        $domain28 = "ksg-c-002.cc.msftcloud.click" nocase
        $domain29 = "ktr-cn-001.amscloudhost.com" nocase
        $domain30 = "ktr-cn-002.amscloudhost.com" nocase
        $domain31 = "l-dn-01.msftcloud.click" nocase
        $domain32 = "l-dn-02.msftcloud.click" nocase
        $domain33 = "l3-dn-01.servicehost.click" nocase
        $domain34 = "l4-dn-01.servicehost.click" nocase
        $domain35 = "l7-dn-01.servicehost.click" nocase
        $domain36 = "linkedin-cloud-manager.servicehost.click" nocase
        $domain37 = "live.airemoteplant.workers.dev" nocase
        $domain38 = "live.itsmartuniverse.workers.dev" nocase
        $domain39 = "m-dn-001.amscloudhost.com" nocase
        $domain40 = "m-dn-002.amscloudhost.com" nocase
        $domain41 = "mainsts-01.cn.alphastoned.pro" nocase
        $domain42 = "mia.nl.tab.digital" nocase
        $domain43 = "msftcloud.click" nocase
        $domain44 = "mtk-cn-001.amscloudhost.com" nocase
        $domain45 = "mtk-cn-002.amscloudhost.com" nocase
        $domain46 = "quiet.msftlivecloudsrv.workers.dev" nocase
        $domain47 = "rl-cn-s-001.amscloudhost.com" nocase
        $domain48 = "servicehost.click" nocase
        $domain49 = "sm.vbigdatasolutions.workers.dev" nocase
        $domain50 = "ss-cn-001.amscloudhost.com" nocase
        $domain51 = "ss-cn-002.amscloudhost.com" nocase
        $domain52 = "sup.wgsphere.workers.dev" nocase
        $domain53 = "tdnmouse.atspace.eu" nocase
        $domain54 = "test.amscloudhost.com" nocase
        $domain55 = "trur-c-001.cc.msftcloud.click" nocase
        $domain56 = "wgroadcdn.workers.dev" nocase
        $domain57 = "wgsphere.workers.dev" nocase
        $ip58 = "188.130.207.253"
        $ip59 = "193.176.158.30"

    condition:
        any of them
}

rule APT_RNEXUS {
    meta:
        description = "Indicators associated with APT RNEXUS"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "com-securitysettingpage.tk" nocase
        $domain1 = "id4242.ga" nocase
        $domain2 = "id833.ga" nocase
        $domain3 = "id834.ga" nocase
        $domain4 = "id9954.gq" nocase
        $domain5 = "mail-google-login.blogspot.com" nocase

    condition:
        any of them
}

rule APT_RUSTICWEB {
    meta:
        description = "Indicators associated with APT RUSTICWEB"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "apsdighi.estttsec.in" nocase
        $domain1 = "awesscholarship.in" nocase
        $domain2 = "epar.in" nocase
        $domain3 = "estttsec.in" nocase
        $domain4 = "nicdsa.estttsec.in" nocase
        $domain5 = "parichay.epar.in" nocase

    condition:
        any of them
}

rule APT_SAGUARO {
    meta:
        description = "Indicators associated with APT SAGUARO"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "eduarditopallares.mooo.com" nocase

    condition:
        any of them
}

rule APT_SANDMAN {
    meta:
        description = "Indicators associated with APT SANDMAN"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "encagil.com" nocase
        $domain1 = "explorecell.com" nocase
        $domain2 = "mode.encagil.com" nocase
        $domain3 = "ssl.explorecell.com" nocase

    condition:
        any of them
}

rule APT_SANDWORM {
    meta:
        description = "Indicators associated with APT SANDWORM"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt44, blackenergy, quedagh"

    strings:
        $domain0 = "1o.cdn-googel.com" nocase
        $domain1 = "2zilmiystfbjib2k4hvhpnv2uhni4ax5ce4xlpb7swkjimfnszxbkaid.onion" nocase
        $domain2 = "365softupdate.com" nocase
        $domain3 = "389424.xyz" nocase
        $domain4 = "445600.xyz" nocase
        $domain5 = "4b.cdn-banamex.com" nocase
        $domain6 = "abaronaweb.net" nocase
        $domain7 = "account-check.hostapp.link" nocase
        $domain8 = "account-googlmail.ml" nocase
        $domain9 = "account-loginserv.com" nocase
        $domain10 = "account.adfs.kyivstar.online" nocase
        $domain11 = "accounts.google-account-settings.spdup.art" nocase
        $domain12 = "activationsmicrosoft.com" nocase
        $domain13 = "adfs.kyivstar.online" nocase
        $domain14 = "adobeprotectcheck.com" nocase
        $domain15 = "ads.ew.com.cn" nocase
        $domain16 = "ads.tolinkhub.com" nocase
        $domain17 = "aiads.best" nocase
        $domain18 = "akamaizes.com" nocase
        $domain19 = "all-invite.org" nocase
        $domain20 = "allserve.xyz" nocase
        $domain21 = "annualgieconferenceinmunich2024.com" nocase
        $domain22 = "antimailspam.com" nocase
        $domain23 = "api-to-now.allserve.xyz" nocase
        $domain24 = "api.beesapp.top" nocase
        $domain25 = "api.budandan.com" nocase
        $domain26 = "api.chaboshi.cc" nocase
        $domain27 = "api.click2mine.top" nocase
        $domain28 = "api.degendogs.top" nocase
        $domain29 = "api.fastrig.top" nocase
        $domain30 = "api.globalsimc.com" nocase
        $domain31 = "api.gmc-doge.top" nocase
        $domain32 = "api.jackpotsure.win" nocase
        $domain33 = "api.luckytonspin.top" nocase
        $domain34 = "api.omgton.xyz" nocase
        $domain35 = "api.plantton.top" nocase
        $domain36 = "api.powerdigger.top" nocase
        $domain37 = "api.powerton.top" nocase
        $domain38 = "api.surewinsgjackpot.com" nocase
        $domain39 = "api.tonblastrun.top" nocase
        $domain40 = "api.tonchainer.top" nocase
        $domain41 = "api.toncore.top" nocase
        $domain42 = "api.tondaily.top" nocase
        $domain43 = "api.tondrillx.top" nocase
        $domain44 = "api.tonengine.top" nocase
        $domain45 = "api.tonfarmers.top" nocase
        $domain46 = "api.tonforgex.top" nocase
        $domain47 = "api.tonhive.top" nocase
        $domain48 = "api.tonmineplus.top" nocase
        $domain49 = "api.tonow.top" nocase
        $domain50 = "api.tonrushgo.top" nocase
        $domain51 = "api.tonvaultchain.top" nocase
        $domain52 = "api.tribikauction.co.id" nocase
        $domain53 = "api.urvega.com" nocase
        $domain54 = "api.xmtk01.xyz" nocase
        $domain55 = "api.xsms.ng" nocase
        $domain56 = "api.yangsany.cn" nocase
        $domain57 = "apiali.huangma188.cc" nocase
        $domain58 = "apidocs.ataas.cl" nocase
        $domain59 = "aplusdesktop.workers.dev" nocase
        $domain60 = "aplusmodgovua.workers.dev" nocase
        $domain61 = "app.chaboshi.cc" nocase
        $domain62 = "armylpus.workers.dev" nocase
        $domain63 = "armyplus-desktop.workers.dev" nocase
        $domain64 = "aut0mat.info" nocase
        $domain65 = "backup.yuhspace.top" nocase
        $domain66 = "bbxgames.top" nocase
        $domain67 = "beesapp.top" nocase
        $domain68 = "beta-0-110.armyplus-desktop.workers.dev" nocase
        $domain69 = "beta-0-2237.desktopapluscom.workers.dev" nocase
        $domain70 = "bitooex.com" nocase
        $domain71 = "bka.im" nocase
        $domain72 = "bot.swapbot.ru" nocase
        $domain73 = "botservice.tgtool.org" nocase
        $domain74 = "budandan.com" nocase
        $domain75 = "cazino-game.com" nocase
        $domain76 = "cdn-banamex.com" nocase
        $domain77 = "cdn-googel.com" nocase
        $domain78 = "cdn-health-service.com" nocase
        $domain79 = "cdn-images-world.com" nocase
        $domain80 = "cdn-javascript-source.com" nocase
        $domain81 = "cdn-sat.com" nocase
        $domain82 = "cdnauthsoft.com" nocase
        $domain83 = "cfaccount.ccwu.cc" nocase
        $domain84 = "chaboshi.cc" nocase
        $domain85 = "checknetworkstatus.com" nocase
        $domain86 = "checknetwstatus.com" nocase
        $domain87 = "checksystem.nl" nocase
        $domain88 = "claud.in" nocase
        $domain89 = "click2mine.top" nocase
        $domain90 = "cloud-sync.org" nocase
        $domain91 = "cloue.link" nocase
        $domain92 = "codvya.cc" nocase
        $domain93 = "cohpoint.com" nocase
        $domain94 = "cols.melfordco.com" nocase
        $domain95 = "convoai.club" nocase
        $domain96 = "ctulocal1.com" nocase
        $domain97 = "cxim.asia" nocase
        $domain98 = "darkett.ddns.net" nocase
        $domain99 = "darksea.ddns.net" nocase
        $ip100 = "1.9.85.247"
        $ip101 = "1.9.85.247"
        $ip102 = "1.9.85.247"
        $ip103 = "1.9.85.247"
        $ip104 = "1.9.85.247"
        $ip105 = "1.9.85.247"
        $ip106 = "1.9.85.247"
        $ip107 = "1.9.85.248"
        $ip108 = "1.9.85.248"
        $ip109 = "1.9.85.248"
        $ip110 = "1.9.85.248"
        $ip111 = "1.9.85.248"
        $ip112 = "1.9.85.248"
        $ip113 = "1.9.85.248"
        $ip114 = "1.9.85.249"
        $ip115 = "1.9.85.249"
        $ip116 = "1.9.85.249"
        $ip117 = "1.9.85.249"
        $ip118 = "1.9.85.249"
        $ip119 = "1.9.85.249"
        $ip120 = "1.9.85.249"
        $ip121 = "1.9.85.252"
        $ip122 = "1.9.85.252"
        $ip123 = "1.9.85.252"
        $ip124 = "1.9.85.252"
        $ip125 = "1.9.85.252"
        $ip126 = "1.9.85.252"
        $ip127 = "1.9.85.252"
        $ip128 = "1.9.85.253"
        $ip129 = "1.9.85.253"
        $ip130 = "1.9.85.253"
        $ip131 = "1.9.85.253"
        $ip132 = "1.9.85.253"
        $ip133 = "1.9.85.253"
        $ip134 = "1.9.85.253"
        $ip135 = "1.9.85.254"
        $ip136 = "1.9.85.254"
        $ip137 = "1.9.85.254"
        $ip138 = "1.9.85.254"
        $ip139 = "1.9.85.254"
        $ip140 = "1.9.85.254"
        $ip141 = "1.9.85.254"
        $ip142 = "100.43.220.234"
        $ip143 = "100.43.220.234"
        $ip144 = "100.43.220.234"
        $ip145 = "100.43.220.234"
        $ip146 = "100.43.220.234"
        $ip147 = "100.43.220.234"
        $ip148 = "100.43.220.234"
        $ip149 = "100.43.220.234"

    condition:
        any of them
}

rule APT_SAURON {
    meta:
        description = "Indicators associated with APT SAURON"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bikessport.com" nocase
        $domain1 = "flowershop22.110mb.com" nocase
        $domain2 = "myhomemusic.com" nocase
        $domain3 = "rapidcomments.com" nocase
        $domain4 = "wildhorses.awardspace.info" nocase

    condition:
        any of them
}

rule APT_SCANBOX {
    meta:
        description = "Indicators associated with APT SCANBOX"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "bak.mailaunch.com" nocase
        $domain1 = "file.googlecaches.com" nocase
        $domain2 = "gtm.googlecaches.com" nocase
        $domain3 = "js.googlewebcache.com" nocase
        $domain4 = "owa.outlookssl.com" nocase
        $domain5 = "us-mg6.mail.yahoo.mailaunch.com" nocase

    condition:
        any of them
}

rule APT_SCARLETMIMIC {
    meta:
        description = "Indicators associated with APT SCARLETMIMIC"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "fakem, fakemrat"

    strings:
        $domain0 = "aaa123.spdns.de" nocase
        $domain1 = "account.websurprisemail.com" nocase
        $domain2 = "accounts.yourturbe.org" nocase
        $domain3 = "addi.apple.cloudns.org" nocase
        $domain4 = "addnow.zapto.org" nocase
        $domain5 = "admin.spdns.org" nocase
        $domain6 = "alma.apple.cloudns.org" nocase
        $domain7 = "angleegg.ddns.us" nocase
        $domain8 = "angleegg.xxxy.info" nocase
        $domain9 = "apple.lenovositegroup.com" nocase
        $domain10 = "apple12.co.cc" nocase
        $domain11 = "apple12.crabdance.com" nocase
        $domain12 = "avira.suroot.com" nocase
        $domain13 = "bailee.alanna.cloudns.biz" nocase
        $domain14 = "bee.aoto.cloudns.org" nocase
        $domain15 = "bits.githubs.net" nocase
        $domain16 = "book.websurprisemail.com" nocase
        $domain17 = "clean.popqueen.cloudns.org" nocase
        $domain18 = "desk.websurprisemail.com" nocase
        $domain19 = "detail43.myfirewall.org" nocase
        $domain20 = "dolat.diyarpakzimin.com" nocase
        $domain21 = "dolat.websurprisemail.com" nocase
        $domain22 = "dolet.websurprisemail.com" nocase
        $domain23 = "economy.spdns.de" nocase
        $domain24 = "economy.spdns.eu" nocase
        $domain25 = "eemete.freetcp.com" nocase
        $domain26 = "email.googmail.org" nocase
        $domain27 = "endless.zapto.org" nocase
        $domain28 = "firefox.spdns.de" nocase
        $domain29 = "firewallupdate.firewall-gateway.net" nocase
        $domain30 = "fish.seafood.cloudns.org" nocase
        $domain31 = "freeavg.sites.net" nocase
        $domain32 = "freeavg.sytes.net" nocase
        $domain33 = "freeonline.3d-game.com" nocase
        $domain34 = "ftp112.lenta.cloudns.pw" nocase
        $domain35 = "github.ignorelist.com" nocase
        $domain36 = "googmail.com" nocase
        $domain37 = "googmail.org" nocase
        $domain38 = "gorlan.cloudns.pro" nocase
        $domain39 = "ibmcorp.slyip.com" nocase
        $domain40 = "intersecurity.firewall-gateway.com" nocase
        $domain41 = "islam.youtubesitegroup.com" nocase
        $domain42 = "kaspersky.firewall-gateway.net" nocase
        $domain43 = "kasperskysecurity.firewall-gateway.com" nocase
        $domain44 = "kissecurity.firewall-gateway.net" nocase
        $domain45 = "lemondtree.freetcp.com" nocase
        $domain46 = "liumingzhen.myftp.org" nocase
        $domain47 = "liumingzhen.zapto.org" nocase
        $domain48 = "mail.firewall-gateway.com" nocase
        $domain49 = "mareva.catherine.cloudns.us" nocase
        $domain50 = "mm.lenovositegroup.com" nocase
        $domain51 = "muslim.islamhood.net" nocase
        $domain52 = "n.popqueen.cloudns.org" nocase
        $domain53 = "news.firewall-gateway.com" nocase
        $domain54 = "news.googmail.org" nocase
        $domain55 = "oic-oci.3-a.net" nocase
        $domain56 = "opero.spdns.org" nocase
        $domain57 = "otcgk.border.cloudns.pw" nocase
        $domain58 = "p.klark.cloudns.in" nocase
        $domain59 = "polat.googmail.org" nocase
        $domain60 = "ppcc.vasilevich.cloudns.info" nocase
        $domain61 = "press.ufoneconference.com" nocase
        $domain62 = "qq.ufoneconference.com" nocase
        $domain63 = "qq.yourturbe.org" nocase
        $domain64 = "sisiow.slyip.com" nocase
        $domain65 = "sys.firewall-gateway.net" nocase
        $domain66 = "update.googmail.org" nocase
        $domain67 = "uprnd.flnet.org" nocase
        $domain68 = "uyghur.25u.com" nocase
        $domain69 = "uyghuri.mrface.com" nocase
        $domain70 = "video.googmail.org" nocase
        $domain71 = "vip.yahoo.cloudns.info" nocase
        $domain72 = "webmail.yourturbe.org" nocase
        $domain73 = "worldwildlife.effers.com" nocase
        $domain74 = "yourturbe.org" nocase
        $domain75 = "youturbe.co.cc" nocase
        $domain76 = "yycc.mrbonus.com" nocase
        $domain77 = "ziba.lenovositegroup.com" nocase
        $domain78 = "zjhao.dtdns.net" nocase
        $ip79 = "153.148.120.217"
        $ip80 = "207.204.225.117"

    condition:
        any of them
}

rule APT_SCIERON {
    meta:
        description = "Indicators associated with APT SCIERON"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "HeaderTip, scarab, spacecolon"

    strings:
        $domain0 = "Markshell.etowns.net" nocase
        $domain1 = "akamaicdnup.com" nocase
        $domain2 = "apple.dynamic-dns.net" nocase
        $domain3 = "autocar.ServeUser.com" nocase
        $domain4 = "autocar.suroot.com" nocase
        $domain5 = "b.688.org" nocase
        $domain6 = "blackblog.chatnook.com" nocase
        $domain7 = "bulldog.toh.info" nocase
        $domain8 = "cdnupdate.net" nocase
        $domain9 = "cew58e.xxxy.info" nocase
        $domain10 = "coastnews.darktech.org" nocase
        $domain11 = "d.piii.net" nocase
        $domain12 = "d1lhk2kflvant7.cloudfront.net" nocase
        $domain13 = "demon.4irc.com" nocase
        $domain14 = "dynamic.ddns.mobi" nocase
        $domain15 = "ebook.port25.biz" nocase
        $domain16 = "expert.4irc.com" nocase
        $domain17 = "football.mrbasic.com" nocase
        $domain18 = "gjjb.flnet.org" nocase
        $domain19 = "imirnov.ddns.info" nocase
        $domain20 = "jingnan88.chatnook.com" nocase
        $domain21 = "lehnjb.epac.to" nocase
        $domain22 = "lockbitblog.info" nocase
        $domain23 = "logoff.25u.com" nocase
        $domain24 = "logoff.ddns.info" nocase
        $domain25 = "ls910329.my03.com" nocase
        $domain26 = "mailru.25u.com" nocase
        $domain27 = "mert.my03.com" nocase
        $domain28 = "mydear.ddns.info" nocase
        $domain29 = "nazgul.zyns.com" nocase
        $domain30 = "ndcinformation.acmetoy.com" nocase
        $domain31 = "newdyndns.scieron.com" nocase
        $domain32 = "newoutlook.darktech.org" nocase
        $domain33 = "photocard.4irc.com" nocase
        $domain34 = "pricetag.deaftone.com" nocase
        $domain35 = "product2020.mrbasic.com" nocase
        $domain36 = "rubberduck.gotgeeks.com" nocase
        $domain37 = "service.authorizeddns.net" nocase
        $domain38 = "shutdown.25u.com" nocase
        $domain39 = "sorry.ns2.name" nocase
        $domain40 = "ss.688.org" nocase
        $domain41 = "sskill.b0ne.com" nocase
        $domain42 = "sys.688.org" nocase
        $domain43 = "text-First.flnet.org" nocase
        $domain44 = "text-first.trickip.org" nocase
        $domain45 = "u.cbu.net" nocase
        $domain46 = "u.piii.net" nocase
        $domain47 = "up.awiki.org" nocase
        $domain48 = "up.vctel.com" nocase
        $domain49 = "update.cbu.net" nocase
        $domain50 = "update.inet2.org" nocase
        $domain51 = "us.notfound.my.id" nocase
        $domain52 = "uudog.4pu.com" nocase
        $domain53 = "will-smith.dtdns.net" nocase
        $domain54 = "yellowblog.flnet.org" nocase
        $ip55 = "104.155.198.25"

    condition:
        any of them
}

rule APT_SEAFLOWER {
    meta:
        description = "Indicators associated with APT SEAFLOWER"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "74871011.huliqianbao.com" nocase
        $domain1 = "app.imztoken.xyz" nocase
        $domain2 = "bnb.lnfura.org" nocase
        $domain3 = "bsc.lnfura.org" nocase
        $domain4 = "btc.lnfura.org" nocase
        $domain5 = "colnbase.homes" nocase
        $domain6 = "copy.lnfura.org" nocase
        $domain7 = "eth.lnfura.org" nocase
        $domain8 = "facai.im" nocase
        $domain9 = "imztoken.xyz" nocase
        $domain10 = "lnfura.io" nocase
        $domain11 = "lnfura.org" nocase
        $domain12 = "mainnet.lnfura.io" nocase
        $domain13 = "mainnet.lnfura.org" nocase
        $domain14 = "manage.lnfura.io" nocase
        $domain15 = "metanask.cc" nocase
        $domain16 = "som-coinbase.com" nocase
        $domain17 = "test.lnfura.org" nocase
        $domain18 = "token18.app" nocase
        $domain19 = "trx.lnfura.org" nocase

    condition:
        any of them
}

rule APT_SECTORA05 {
    meta:
        description = "Indicators associated with APT SECTORA05"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "acount-qooqle.pe.hu" nocase
        $domain1 = "ago2.co.kr" nocase
        $domain2 = "ahnniab.esy.es" nocase
        $domain3 = "aiyac-updaite.hol.es" nocase
        $domain4 = "daum-safety-team.esy.es" nocase
        $domain5 = "daum-settting.hol.es" nocase
        $domain6 = "gyjmc.com" nocase
        $domain7 = "jejuseongahn.org" nocase
        $domain8 = "jundosase.cafe24.com" nocase
        $domain9 = "kuku675.site11.com" nocase
        $domain10 = "kuku79.herobo.com" nocase
        $domain11 = "mail-service.pe.hu" nocase
        $domain12 = "mail-support.esy.es" nocase
        $domain13 = "ms-performance.hol.es" nocase
        $domain14 = "msperformance.hol.es" nocase
        $domain15 = "my-homework.890m.com" nocase
        $domain16 = "myacccounts-goggle.hol.es" nocase
        $domain17 = "myaccounnts-goggle.esy.es" nocase
        $domain18 = "myprofileacc.pe.hu" nocase
        $domain19 = "nav-mail.hol.es" nocase
        $domain20 = "navem-rnail.hol.es" nocase
        $domain21 = "need-nver.hol.es" nocase
        $domain22 = "nid-mail.esy.es" nocase
        $domain23 = "nid-mail.hol.es" nocase
        $domain24 = "nid-mail.pe.hu" nocase
        $domain25 = "nid-naver.hol.es" nocase
        $domain26 = "nid-never.pe.hu" nocase
        $domain27 = "qqoqle-centering.esy.es" nocase
        $domain28 = "rnyacount-jpadmin.hol.es" nocase
        $domain29 = "safe-naver-mail.pe.hu" nocase
        $domain30 = "suppcrt-seourity.esy.es" nocase

    condition:
        any of them
}

rule APT_SHAMOON {
    meta:
        description = "Indicators associated with APT SHAMOON"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "analytics-google.org" nocase
        $domain1 = "go-microstf.com" nocase
        $domain2 = "key8854321.pub" nocase
        $domain3 = "maps-modon.club" nocase
        $domain4 = "mol.com-ho.me" nocase
        $domain5 = "mynetwork.ddns.net" nocase
        $domain6 = "ntg-sa.com" nocase
        $domain7 = "possibletarget.ddns.com" nocase
        $domain8 = "winappupdater.com" nocase
        $domain9 = "winupdater.com" nocase

    condition:
        any of them
}

rule APT_SHARPPANDA {
    meta:
        description = "Indicators associated with APT SHARPPANDA"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "office.oiqezet.com" nocase
        $domain1 = "oiqezet.com" nocase
        $domain2 = "openxmlformats.shop" nocase
        $domain3 = "schemas.openxmlformats.shop" nocase
        $domain4 = "template-content.azurecloudapp.workers.dev" nocase
        $ip5 = "107.148.165.151"
        $ip6 = "13.236.189.80"
        $ip7 = "45.121.146.88"
        $ip8 = "45.76.190.210"
        $ip9 = "45.91.225.139"

    condition:
        any of them
}

rule APT_SHIQIANG {
    meta:
        description = "Indicators associated with APT SHIQIANG"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "newyorkonlin.com" nocase
        $domain1 = "tibetcongress.oicp.net" nocase

    condition:
        any of them
}

rule APT_SIDEWINDER {
    meta:
        description = "Indicators associated with APT SIDEWINDER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-04, apt-c-24, apt-q-39"

    strings:
        $domain0 = "0range.site" nocase
        $domain1 = "0ultook.live" nocase
        $domain2 = "1.modp-pk.org" nocase
        $domain3 = "101c4a583c3acdd2a06ca2fb183cf995fgd55fghf67dhf7dhf7dhnfks7.pages.dev" nocase
        $domain4 = "101c4a583c3acdd2afd06ca2fb183cf995sdfsdh54jkdfgh54893489h5.pages.dev" nocase
        $domain5 = "101c4a583c3acdd2dfgn54990fgmkl5i90ghml569ig06ca2fb183cf995.pages.dev" nocase
        $domain6 = "101c4a5fdjfjkf8fg90fksd9dfslsd0fk83c3acdd2a06ca2fb183cf995.pages.dev" nocase
        $domain7 = "109.176.30.212.sslip.io" nocase
        $domain8 = "126-com.live" nocase
        $domain9 = "126mail-cn.com" nocase
        $domain10 = "163inc.org" nocase
        $domain11 = "168-gov.info" nocase
        $domain12 = "16bz5.pmreco.xyz" nocase
        $domain13 = "17067699af72f31706fgjkf5kg9j4990gk950.netlify.app" nocase
        $domain14 = "172.86.92.150.sslip.io" nocase
        $domain15 = "1846m.pmreco.xyz" nocase
        $domain16 = "1c1157fa.caa.update.customs-lk.org" nocase
        $domain17 = "1d06bfb2.check.update.fia-gov.org" nocase
        $domain18 = "1d06bfb2.local.update.fia-gov.org" nocase
        $domain19 = "1d06bfb2.scan.update.fia-gov.org" nocase
        $domain20 = "203-124351878443.hopto.org" nocase
        $domain21 = "234rewr44dfs34sdf43454353fd4ffg345rr4.netlify.app" nocase
        $domain22 = "24170-40494.bacloud.info" nocase
        $domain23 = "2672ewr5403894534fgdgfd5907e44fdfgdfg67088gdfgfd90e2cbd8b6.pages.dev" nocase
        $domain24 = "2aeb306b-4c5f-4cc6-a7a2-6fcd96612b9d.us-east-1.cloud.genez.io" nocase
        $domain25 = "2let.org" nocase
        $domain26 = "2r.nrtcpk-net.com" nocase
        $domain27 = "38273409.mail-defence-lk-loging-horde.pages.dev" nocase
        $domain28 = "3nxyc.pmreco.xyz" nocase
        $domain29 = "423743f1-53d2-41bf-9dba-e1e0b7c8f460.pmreco.xyz" nocase
        $domain30 = "435fdgfd-fgh675gh56jh-65jhg65ghjytu65.netlify.app" nocase
        $domain31 = "4yj7f.pmreco.xyz" nocase
        $domain32 = "5673696e-bcf9-4a34-848d-2e6875b0561e.us-east-1.cloud.genez.io" nocase
        $domain33 = "5vs9r.pmreco.xyz" nocase
        $domain34 = "63inc.com" nocase
        $domain35 = "64115cb6.check.update.fia-gov.org" nocase
        $domain36 = "6441056b613c32a9.dwnlld.info" nocase
        $domain37 = "6dbb77fd-6d9d-415e-b414-3d1051cd33f4.dytt888.net" nocase
        $domain38 = "753fa5b2.check.update.fia-gov.org" nocase
        $domain39 = "7b1271c3-0158-4f94-b54e-d51a4be1cfc4.us-east-1.cloud.genez.io" nocase
        $domain40 = "7ef1996f-c463-4540-936a-70d0fd477f98.live-co.org" nocase
        $domain41 = "81-cn.ddns.net" nocase
        $domain42 = "81-cn.info" nocase
        $domain43 = "85476ee3-a4b9-4815-bd1d-68653205e378.us-east-1.cloud.genez.io" nocase
        $domain44 = "8ad94e36.cdn-caa-sco.pages.dev" nocase
        $domain45 = "96c54.pmreco.xyz" nocase
        $domain46 = "982m31.pmreco.xyz" nocase
        $domain47 = "9af72fg4jg75hg8jg94kg94k9fk390gk4170674tr69bf1f766cdec1d11.pages.dev" nocase
        $domain48 = "9af72fg4jg75hg8jg9dfghhfgdh5666k41706769d32bf1f766cdec1d1.pages.dev" nocase
        $domain49 = "9af72fg4jg75hg8jg9dfghhfgdh5666k41706769d32bf1f766cdec1d11.pages.dev" nocase
        $domain50 = "9t.fetchdrives.info" nocase
        $domain51 = "a.bc.1d06bfb2.check.update.fia-gov.org" nocase
        $domain52 = "a.bc.1d06bfb2.local.update.fia-gov.org" nocase
        $domain53 = "a.bc.1d06bfb2.scan.update.fia-gov.org" nocase
        $domain54 = "a.bc.64115cb6.check.update.fia-gov.org" nocase
        $domain55 = "a.fetchdrive.info" nocase
        $domain56 = "a5936441-e402-41e3-b02b-75af112074b5.org-co.net" nocase
        $domain57 = "a6dff163-e0b9-49c9-87e4-357f761f3c3b.us-east-1.cloud.genez.io" nocase
        $domain58 = "aa173.bank-ok.com" nocase
        $domain59 = "aapletv.org" nocase
        $domain60 = "abc.bol-north.com" nocase
        $domain61 = "academy.lesporc.live" nocase
        $domain62 = "acc.pk-govt.net" nocase
        $domain63 = "acenent.site" nocase
        $domain64 = "acfinang.shop" nocase
        $domain65 = "acrobat.paknavy-pk.org" nocase
        $domain66 = "active.roteh.site" nocase
        $domain67 = "admin.grabfiles.org" nocase
        $domain68 = "admin.onesom.biz" nocase
        $domain69 = "adobe.pdf-downlod.com" nocase
        $domain70 = "adobe.updatepdf.workers.dev" nocase
        $domain71 = "adobeglobal.com" nocase
        $domain72 = "advancedhealth.medicallab.site" nocase
        $domain73 = "advisary.army-govbd.info" nocase
        $domain74 = "advisories-sgcustoms.d0cumentview.info" nocase
        $domain75 = "advisory-cabinetgpk.servehttp.com" nocase
        $domain76 = "advisory.army-govbd.info" nocase
        $domain77 = "advisory.info-bdgov.com" nocase
        $domain78 = "advisory.ndma-govpk.co" nocase
        $domain79 = "aeltron.xyz" nocase
        $domain80 = "aeryple.xyz" nocase
        $domain81 = "afcat.xyz" nocase
        $domain82 = "afd-bdmil.cdn-pak.net" nocase
        $domain83 = "afd.edu-cx.org" nocase
        $domain84 = "afdinfo786.bdgov.info" nocase
        $domain85 = "afdtrg.nrdi-gov.com" nocase
        $domain86 = "afg-refugee.net" nocase
        $domain87 = "afghannewsnetwork.com" nocase
        $domain88 = "afmat.tech" nocase
        $domain89 = "afohs.mod-pak.co" nocase
        $domain90 = "afrepublic.xyz" nocase
        $domain91 = "agarg.tech" nocase
        $domain92 = "agency.lesporc.live" nocase
        $domain93 = "agenda-talking-point-for-army.up.railway.app" nocase
        $domain94 = "agent.onesom.biz" nocase
        $domain95 = "ahsaanullaahkhan.workers.dev" nocase
        $domain96 = "ai.mofagov.online" nocase
        $domain97 = "ailyun.live" nocase
        $domain98 = "aitkenspencelogistics.mofa.live" nocase
        $domain99 = "akamai.servehttp.com" nocase
        $ip100 = "110.10.176.193"
        $ip101 = "141.136.0.91"
        $ip102 = "144.91.72.17"
        $ip103 = "149.102.131.122"
        $ip104 = "151.236.11.147"
        $ip105 = "164.68.108.153"
        $ip106 = "164.68.108.153"
        $ip107 = "164.68.108.153"
        $ip108 = "167.86.94.42"
        $ip109 = "173.212.242.43"
        $ip110 = "185.159.128.117"
        $ip111 = "185.225.17.239"
        $ip112 = "185.225.19.46"
        $ip113 = "185.225.19.46"
        $ip114 = "193.200.16.230"
        $ip115 = "202.58.104.100"
        $ip116 = "213.227.154.175"
        $ip117 = "31.15.17.230"
        $ip118 = "31.58.137.246"
        $ip119 = "38.60.235.109"
        $ip120 = "46.8.226.5"
        $ip121 = "47.236.177.123"
        $ip122 = "47.76.135.130"
        $ip123 = "47.84.196.148"
        $ip124 = "5.230.40.141"
        $ip125 = "5.230.42.202"
        $ip126 = "5.230.43.203"
        $ip127 = "5.230.52.133"
        $ip128 = "5.230.54.162"
        $ip129 = "5.230.54.63"
        $ip130 = "5.230.55.29"
        $ip131 = "5.230.70.181"
        $ip132 = "5.230.71.148"
        $ip133 = "5.230.74.96"
        $ip134 = "5.230.77.142"
        $ip135 = "5.252.178.27"
        $ip136 = "5.252.178.27"
        $ip137 = "62.171.172.199"
        $ip138 = "62.171.172.199"
        $ip139 = "62.171.172.199"
        $ip140 = "62.171.187.53"
        $ip141 = "62.171.187.53"
        $ip142 = "62.171.187.53"
        $ip143 = "64.46.102.122"
        $ip144 = "64.46.102.26"
        $ip145 = "64.46.102.63"
        $ip146 = "74.125.196.113"
        $ip147 = "8.222.250.160"
        $ip148 = "89.46.65.19"
        $ip149 = "91.193.18.248"

    condition:
        any of them
}

rule APT_SILENCE {
    meta:
        description = "Indicators associated with APT SILENCE"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "1bmank.ru" nocase
        $domain1 = "1m-lombard.ru" nocase
        $domain2 = "1m6ank.ru" nocase
        $domain3 = "1mbabk.ru" nocase
        $domain4 = "1mbakn.ru" nocase
        $domain5 = "1mbamk.ru" nocase
        $domain6 = "1mbanc.ru" nocase
        $domain7 = "1mbanck.ru" nocase
        $domain8 = "1mbang.ru" nocase
        $domain9 = "1mbanj.ru" nocase
        $domain10 = "1mbank.biz" nocase
        $domain11 = "1mbank.info" nocase
        $domain12 = "1mbank.me" nocase
        $domain13 = "1mbank.net" nocase
        $domain14 = "1mbank.online" nocase
        $domain15 = "1mbank.su" nocase
        $domain16 = "1mbankru.ru" nocase
        $domain17 = "1mbanl.ru" nocase
        $domain18 = "1mbnak.ru" nocase
        $domain19 = "1mbonk.ru" nocase
        $domain20 = "1mbsnk.ru" nocase
        $domain21 = "1mbunk.ru" nocase
        $domain22 = "1mcredit.ru" nocase
        $domain23 = "1mliked.ru" nocase
        $domain24 = "1mnank.ru" nocase
        $domain25 = "1mvank.ru" nocase
        $domain26 = "1mvklad.ru" nocase
        $domain27 = "1nnbank.ru" nocase
        $domain28 = "abp.ru" nocase
        $domain29 = "bankrebres.ru" nocase
        $domain30 = "basch.eu" nocase
        $domain31 = "cardisprom.ru" nocase
        $domain32 = "counterstat.club" nocase
        $domain33 = "counterstat.pw" nocase
        $domain34 = "fpbank.ru" nocase
        $domain35 = "itablex.com" nocase
        $domain36 = "maybank.ru" nocase
        $domain37 = "mobilecommerzbank.com" nocase
        $domain38 = "morefin.ru" nocase
        $domain39 = "odinmbank.ru" nocase
        $domain40 = "onembank.ru" nocase
        $domain41 = "pharmk.group" nocase
        $domain42 = "xn--1---7cdbdjx3ajbffshlvpuz.xn--p1ai" nocase
        $domain43 = "xn--1--8kcadhu0aibfergltoty.xn--p1ai" nocase
        $domain44 = "xn--1-8sbc1bhi.xn--p1ai" nocase
        $domain45 = "xn--1-8sbydbel6b.xn--p1ai" nocase
        $domain46 = "xn--80absjpcg.com" nocase
        $domain47 = "zaometallniva.ru" nocase
        $ip48 = "185.20.187.89"

    condition:
        any of them
}

rule APT_SILENCERLION {
    meta:
        description = "Indicators associated with APT SILENCERLION"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "cdn.dosya.web.tr" nocase
        $domain1 = "ludo.ezyro.com" nocase
        $domain2 = "samsung.apps.linkpc.net" nocase

    condition:
        any of them
}

rule APT_SILENTLYNX {
    meta:
        description = "Indicators associated with APT SILENTLYNX"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "shadowsilk, hydra saiga"

    strings:
        $domain0 = "accessibleneats.com" nocase
        $domain1 = "accttechllc.com" nocase
        $domain2 = "adm-govuz.com" nocase
        $domain3 = "admin.inboxsession.info" nocase
        $domain4 = "akcloud.top" nocase
        $domain5 = "akersolutoins.com" nocase
        $domain6 = "alandyh.com" nocase
        $domain7 = "albertinamachinery.com" nocase
        $domain8 = "alfhjdumnsulhuehs.com" nocase
        $domain9 = "allcloudindex.com" nocase
        $domain10 = "allocco-ar.com" nocase
        $domain11 = "alpine-hosokawa.net" nocase
        $domain12 = "altendorf-de.com" nocase
        $domain13 = "annons.info" nocase
        $domain14 = "arableaguenews.com" nocase
        $domain15 = "arpimportnl.com" nocase
        $domain16 = "asdnwakalet.net" nocase
        $domain17 = "asmtld.com" nocase
        $domain18 = "atomicenergylab.com" nocase
        $domain19 = "auth.allcloudindex.com" nocase
        $domain20 = "authmailinbox.com" nocase
        $domain21 = "ax47tui83.com" nocase
        $domain22 = "aydemirtek.com" nocase
        $domain23 = "babblnipresses.com" nocase
        $domain24 = "bencoconstructionsllc.com" nocase
        $domain25 = "bestdomblog.com" nocase
        $domain26 = "bestmartsolutions.com" nocase
        $domain27 = "bestunif.com" nocase
        $domain28 = "bluemoono.com" nocase
        $domain29 = "brainytask.tech" nocase
        $domain30 = "brandxoffice.com" nocase
        $domain31 = "breuing-irco.com" nocase
        $domain32 = "brindley-medical.com" nocase
        $domain33 = "cae-gruope.com" nocase
        $domain34 = "cairo-day-trips.com" nocase
        $domain35 = "caprnatic.com" nocase
        $domain36 = "catalog-update-update-microsoft.serveftp.com" nocase
        $domain37 = "catchthestorms.net" nocase
        $domain38 = "check-connection.org" nocase
        $domain39 = "checkingsite.org" nocase
        $domain40 = "citylinefood.com" nocase
        $domain41 = "cm-elevatori.com" nocase
        $domain42 = "cmcrushermachine.com" nocase
        $domain43 = "colombaogrobg.com" nocase
        $domain44 = "consultafacildoc.com" nocase
        $domain45 = "consultasfacildoc.com" nocase
        $domain46 = "converting-system.com" nocase
        $domain47 = "csiwoffshore.com" nocase
        $domain48 = "datosdecuit.com" nocase
        $domain49 = "dl-keepass.info" nocase
        $domain50 = "dmgrnori.com" nocase
        $domain51 = "dmsplasts.com" nocase
        $domain52 = "document.hometowncity.cloud" nocase
        $domain53 = "document.mailboxarea.cloud" nocase
        $domain54 = "document.webmailsession.com" nocase
        $domain55 = "docworldme.com" nocase
        $domain56 = "downloadmailbox.com" nocase
        $domain57 = "e-egov.com" nocase
        $domain58 = "eaglesxv.com" nocase
        $domain59 = "eco-prozestechnik.com" nocase
        $domain60 = "eew-groups.com" nocase
        $domain61 = "elcomen.com" nocase
        $domain62 = "elike-rne.com" nocase
        $domain63 = "elinkexpressltd.com" nocase
        $domain64 = "elldrissi.com" nocase
        $domain65 = "elpisitsinc.com" nocase
        $domain66 = "emails-cloud.com" nocase
        $domain67 = "emiratom.com" nocase
        $domain68 = "emsilgroups.com" nocase
        $domain69 = "enigmaaxis.com" nocase
        $domain70 = "envolvesearch.com" nocase
        $domain71 = "estaterlea.com" nocase
        $domain72 = "etori.info" nocase
        $domain73 = "etunabilar.com" nocase
        $domain74 = "ex.wincorpupdates.com" nocase
        $domain75 = "field-tec.org" nocase
        $domain76 = "filecenter.online" nocase
        $domain77 = "filereader.online" nocase
        $domain78 = "filfilter-tr.com" nocase
        $domain79 = "filorep.com" nocase
        $domain80 = "fob-au.com" nocase
        $domain81 = "garmorgan.com" nocase
        $domain82 = "gdrr.info" nocase
        $domain83 = "geanew.com" nocase
        $domain84 = "geniwatit.com" nocase
        $domain85 = "genmac-it.com" nocase
        $domain86 = "globa-space.com" nocase
        $domain87 = "globexgruop.com" nocase
        $domain88 = "gmvtest9.ddns.net" nocase
        $domain89 = "goodbabiynt.com" nocase
        $domain90 = "greeentom.com" nocase
        $domain91 = "gsbplataforma.com" nocase
        $domain92 = "guidolingiroto.com" nocase
        $domain93 = "gvfimpainti.com" nocase
        $domain94 = "gynovetylesc.com" nocase
        $domain95 = "hamzagill.com" nocase
        $domain96 = "harrellc.com" nocase
        $domain97 = "henigworldwide.com" nocase
        $domain98 = "hgbeerequipment-uk.com" nocase
        $domain99 = "hi053.info" nocase
        $ip100 = "141.98.82.198"
        $ip101 = "141.98.82.198"
        $ip102 = "152.53.20.140"
        $ip103 = "154.31.217.203"
        $ip104 = "172.86.75.237"
        $ip105 = "185.122.171.22"
        $ip106 = "185.62.57.219"
        $ip107 = "193.124.203.226"
        $ip108 = "65.38.120.38"
        $ip109 = "65.38.121.107"
        $ip110 = "72.5.43.100"
        $ip111 = "72.5.43.178"
        $ip112 = "81.19.136.241"
        $ip113 = "81.19.136.241"
        $ip114 = "82.115.223.210"
        $ip115 = "85.209.128.171"
        $ip116 = "85.209.128.171"
        $ip117 = "85.209.128.171"
        $ip118 = "85.209.128.171"
        $ip119 = "85.209.128.171"
        $ip120 = "88.214.26.37"
        $ip121 = "88.214.26.37"
        $ip122 = "96.9.125.168"

    condition:
        any of them
}

rule APT_SIMBAA {
    meta:
        description = "Indicators associated with APT SIMBAA"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "firebasebox.com" nocase

    condition:
        any of them
}

rule APT_SKYCLOAK {
    meta:
        description = "Indicators associated with APT SKYCLOAK"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "vortex werewolf"

    strings:
        $domain0 = "2zrek3mkl72d5b6evpkx2rz2glzrltiorgblpfb2ttg6lacwlsdk4iqd.onion" nocase
        $domain1 = "3xl6xhboulyuez6fuydyhj7pdvkshzn4ogsmgwbb3ukrkvgi6bcwvfyd.onion" nocase
        $domain2 = "e3mnde5uyuxjoztup6t3m7nykbicexbzra76ucligwgsaez65w63y2ad.onion" nocase
        $domain3 = "imnlyhj4mtmtesqrvf7c4ma6dkxeyxw3ae53w6fuz42spndg7zpat6qd.onion" nocase
        $domain4 = "iz4cthf7lios7igq7lvvlgg6xyn5eqowfue5wgsdlgdipueam7av32ad.onion" nocase
        $domain5 = "juliw3eyjz5gx7hup73jbnyeqrdlrzvzxxsbww2tewp3sbh2qtpbasad.onion" nocase
        $domain6 = "kvk46su7d2qi6g4n43syp4zbsf2rihnc6ztj77qtc2ojvewjqvqilnqd.onion" nocase
        $domain7 = "nytiplwknkinobjaeb5tajjiglip3vtaccju6ta7d47u5u64ktrwhrqd.onion" nocase
        $domain8 = "q35x354qfx43klbx5wd2iw7272wrrhcvgwqqbwut44yiui2hw7cz7fyd.onion" nocase
        $domain9 = "uliw3eyjz5gx7hup73jbnyeqrdlrzvzxxsbww2tewp3sbh2qtpbasad.onion" nocase
        $domain10 = "yuknkap4im65njr3tlprnpqwj4h7aal4hrn2tdieg75rpp6fx25hqbyd.onion" nocase
        $ip11 = "176.169.236.210"
        $ip12 = "188.116.26.254"
        $ip13 = "193.138.81.106"
        $ip14 = "74.208.183.104"
        $ip15 = "81.141.112.253"
        $ip16 = "91.208.206.67"
        $ip17 = "95.179.192.8"

    condition:
        any of them
}

rule APT_SNOWMAN {
    meta:
        description = "Indicators associated with APT SNOWMAN"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "ali.blankchair.com" nocase
        $domain1 = "book.flnet.org" nocase
        $domain2 = "cht.blankchair.com" nocase
        $domain3 = "dll.freshdns.org" nocase
        $domain4 = "icybin.flnet.org" nocase
        $domain5 = "info.flnet.org" nocase
        $domain6 = "me.scieron.com" nocase
        $domain7 = "rt.blankchair.com" nocase

    condition:
        any of them
}

rule APT_SOBAKEN {
    meta:
        description = "Indicators associated with APT SOBAKEN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "firmachagent, SPECTR, Vermin"

    strings:
        $domain0 = "aeroua.online" nocase
        $domain1 = "akamaicdn.ru" nocase
        $domain2 = "akamainet021.info" nocase
        $domain3 = "akamainet022.info" nocase
        $domain4 = "akamainet023.info" nocase
        $domain5 = "akamainet024.info" nocase
        $domain6 = "akamainet066.info" nocase
        $domain7 = "akamainet067.info" nocase
        $domain8 = "aviasys.somee.com" nocase
        $domain9 = "cdnakamai.ru" nocase
        $domain10 = "code.ukraero.space" nocase
        $domain11 = "firma.ukraero.space" nocase
        $domain12 = "getmod.host" nocase
        $domain13 = "gw.telegrarn.fun" nocase
        $domain14 = "mail.ukraero.space" nocase
        $domain15 = "mailukr.net" nocase
        $domain16 = "meteolink.host" nocase
        $domain17 = "netbin.host" nocase
        $domain18 = "notifymail.ru" nocase
        $domain19 = "prozorro.online" nocase
        $domain20 = "stormpredictor.host" nocase
        $domain21 = "syncapp.host" nocase
        $domain22 = "tech-adobe.dyndns.biz" nocase
        $domain23 = "telegrarn.fun" nocase
        $domain24 = "ukr.somee.com" nocase
        $domain25 = "ukraero.space" nocase
        $domain26 = "windowsupdate.kiev.ua" nocase

    condition:
        any of them
}

rule APT_SOFACY {
    meta:
        description = "Indicators associated with APT SOFACY"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt28, apt-c-20, sednit"

    strings:
        $domain0 = "000000027.xyz" nocase
        $domain1 = "0x4fc271.tk" nocase
        $domain2 = "0xf4a5.tk" nocase
        $domain3 = "0xf4a54cf56.tk" nocase
        $domain4 = "1000018.xyz" nocase
        $domain5 = "1000020.xyz" nocase
        $domain6 = "100plusapps.com" nocase
        $domain7 = "1221.site" nocase
        $domain8 = "15052021.space" nocase
        $domain9 = "150520212.space" nocase
        $domain10 = "150520213.space" nocase
        $domain11 = "1681683130.website" nocase
        $domain12 = "16868138130.space" nocase
        $domain13 = "1833.site" nocase
        $domain14 = "1oo7.net" nocase
        $domain15 = "200200.duckdns.org" nocase
        $domain16 = "2055.site" nocase
        $domain17 = "2215.site" nocase
        $domain18 = "29572459487545-4543543-543534255-454-35432524-5243523-234543.xyz" nocase
        $domain19 = "2f9348243249382479234343284324023432748892349702394023.xyz" nocase
        $domain20 = "32689657.xyz" nocase
        $domain21 = "32689658.xyz" nocase
        $domain22 = "32689659.xyz" nocase
        $domain23 = "33655990.cyou" nocase
        $domain24 = "34564414564.com" nocase
        $domain25 = "357.duckdns.org" nocase
        $domain26 = "365msoffice.com" nocase
        $domain27 = "47e811dbe2ed0ea8d506af94c1bb7d4c.serveo.net" nocase
        $domain28 = "4895458025-4545445-222435-9635794543-3242314342-234123423728.space" nocase
        $domain29 = "48d83469-d0c6-4ade-8f82-e383fff094b8.webhook.site" nocase
        $domain30 = "512521525-5245451515-985978774-2341235146436.xyz" nocase
        $domain31 = "546874.tk" nocase
        $domain32 = "5thelementq8.com" nocase
        $domain33 = "645547657668787.com" nocase
        $domain34 = "6c7aa72bd5f1d30203b80596f926b2b7.serveo.net" nocase
        $domain35 = "73ce1aae8a9ba738b91040232524f51a.serveo.net" nocase
        $domain36 = "78cc700b31dcd7c7f25fd7b0372259e3.serveo.net" nocase
        $domain37 = "7daysinabudhabi.org" nocase
        $domain38 = "90update.com" nocase
        $domain39 = "910cf351-a05d-4f67-ab8e-6f62cfa8e26d.dnshook.site" nocase
        $domain40 = "92ace7e653e9c32d2af9700592cc96ea.serveo.net" nocase
        $domain41 = "9348243249382479234343284324023432748892349702394023.xyz" nocase
        $domain42 = "9832473219412342343423243242364-34939246823743287468793247237.site" nocase
        $domain43 = "99996665550.fun" nocase
        $domain44 = "99kg.site" nocase
        $domain45 = "9b5uja.am.files.1drv.com" nocase
        $domain46 = "a.zhblz.com" nocase
        $domain47 = "aa.69.mu" nocase
        $domain48 = "aadexpo2014.co.za" nocase
        $domain49 = "abbott-export.com" nocase
        $domain50 = "academl.com" nocase
        $domain51 = "acccountverify.com" nocase
        $domain52 = "accesd-de-desjardins.com" nocase
        $domain53 = "access-apple-login-account.gq" nocase
        $domain54 = "access-google.com" nocase
        $domain55 = "accgmail.com" nocase
        $domain56 = "account-activity-verification-login.ga" nocase
        $domain57 = "account-close-status.com" nocase
        $domain58 = "account-flickr.com" nocase
        $domain59 = "account-microsoftonline.com" nocase
        $domain60 = "account-office365.com" nocase
        $domain61 = "account-verify-comfirmation-info-login.ga" nocase
        $domain62 = "account-verify-comfirmation-info-login.gq" nocase
        $domain63 = "account.password-google.com" nocase
        $domain64 = "accountgooogle.com" nocase
        $domain65 = "accountlogin-inc.ga" nocase
        $domain66 = "accounts-googlc.com" nocase
        $domain67 = "accounts-gooogl.com" nocase
        $domain68 = "accounts-office.fr" nocase
        $domain69 = "accounts-qooqle.com" nocase
        $domain70 = "accounts-updated.com" nocase
        $domain71 = "accounts.rsshotmail.com" nocase
        $domain72 = "accountsgooglemail.com" nocase
        $domain73 = "accountsteam-en.com" nocase
        $domain74 = "accountverify-disableinfo-login.gq" nocase
        $domain75 = "accountverify.com" nocase
        $domain76 = "accountverify.info" nocase
        $domain77 = "acledit.com" nocase
        $domain78 = "acrobatportable.com" nocase
        $domain79 = "actblues.com" nocase
        $domain80 = "action-yandex.ru" nocase
        $domain81 = "activity-yandex.ru" nocase
        $domain82 = "adawareblock.com" nocase
        $domain83 = "adfs-senate.email" nocase
        $domain84 = "adfs-senate.services" nocase
        $domain85 = "adfs.senate.group" nocase
        $domain86 = "adfs.senate.qov.info" nocase
        $domain87 = "adobe-flash-updates.org" nocase
        $domain88 = "adobeincorp.com" nocase
        $domain89 = "adobemainsecurity.com" nocase
        $domain90 = "adobeproduct.com" nocase
        $domain91 = "adobestatistic.com" nocase
        $domain92 = "adobestatistic.org" nocase
        $domain93 = "adobeupdater.org" nocase
        $domain94 = "adobeupdatetechnology.com" nocase
        $domain95 = "adobeupgradeflash.com" nocase
        $domain96 = "advpdxapi.com" nocase
        $domain97 = "aerospacesystem.us.com" nocase
        $domain98 = "afghanistanmfa.net" nocase
        $domain99 = "ahr0cdovlzkyljiymi4ymdkundkvywn0a.0.d.255.adobeproduct.com" nocase
        $ip100 = "101.255.119.42"
        $ip101 = "103.140.186.148"
        $ip102 = "103.140.186.149"
        $ip103 = "103.140.186.155"
        $ip104 = "109.169.15.73"
        $ip105 = "113.160.234.229"
        $ip106 = "128.199.199.187"
        $ip107 = "144.126.202.227"
        $ip108 = "145.249.106.198"
        $ip109 = "148.252.42.42"
        $ip110 = "163.172.67.233"
        $ip111 = "167.114.153.55"
        $ip112 = "168.205.200.55"
        $ip113 = "172.114.170.18"
        $ip114 = "172.114.170.18"
        $ip115 = "174.53.242.108"
        $ip116 = "178.32.251.98"
        $ip117 = "18.157.68.73"
        $ip118 = "18.192.93.86"
        $ip119 = "18.197.239.109"
        $ip120 = "181.209.99.204"
        $ip121 = "184.95.51.172"
        $ip122 = "185.117.88.22"
        $ip123 = "185.117.88.28"
        $ip124 = "185.117.88.29"
        $ip125 = "185.117.88.30"
        $ip126 = "185.117.88.31"
        $ip127 = "185.117.88.50"
        $ip128 = "185.117.88.60"
        $ip129 = "185.117.88.61"
        $ip130 = "185.117.88.62"
        $ip131 = "185.117.89.32"
        $ip132 = "185.117.89.46"
        $ip133 = "185.117.89.47"
        $ip134 = "185.132.17.160"
        $ip135 = "185.141.63.103"
        $ip136 = "185.234.73.58"
        $ip137 = "185.234.73.61"
        $ip138 = "185.234.73.62"
        $ip139 = "185.236.203.53"
        $ip140 = "185.237.166.224"
        $ip141 = "185.237.166.225"
        $ip142 = "185.237.166.226"
        $ip143 = "185.237.166.227"
        $ip144 = "185.237.166.228"
        $ip145 = "185.237.166.229"
        $ip146 = "185.237.166.230"
        $ip147 = "185.237.166.231"
        $ip148 = "185.237.166.232"
        $ip149 = "185.237.166.233"

    condition:
        any of them
}

rule APT_SPACEPIRATES {
    meta:
        description = "Indicators associated with APT SPACEPIRATES"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "0077.x24hr.com" nocase
        $domain1 = "alex.dnset.com" nocase
        $domain2 = "amazon-corp.wikaba.com" nocase
        $domain3 = "api.microft.dynssl.com" nocase
        $domain4 = "app.hostareas.com" nocase
        $domain5 = "apple-corp.changeip.org" nocase
        $domain6 = "as.amazon-corp.wikaba.com" nocase
        $domain7 = "asd.powergame.0077.x24hr.com" nocase
        $domain8 = "bamo.ocry.com" nocase
        $domain9 = "cdnsvc.microft.dynssl.com" nocase
        $domain10 = "chdsjjkrazomg.dhcp.biz" nocase
        $domain11 = "comein.journal.itsaol.com" nocase
        $domain12 = "community.reportsearch.dynamic-dns.net" nocase
        $domain13 = "dnsinfo.microft.dynssl.com" nocase
        $domain14 = "docs.microft.dynssl.com" nocase
        $domain15 = "edge.microft.dynssl.com" nocase
        $domain16 = "elienceso.kozow.com" nocase
        $domain17 = "erdcserver.microft.dynssl.com" nocase
        $domain18 = "eset.zzux.com" nocase
        $domain19 = "exowa.microft.dynssl.com" nocase
        $domain20 = "fgjhkergvlimdfg2.wikaba.com" nocase
        $domain21 = "fileserverrt.reportsearch.dynamic-dns.net" nocase
        $domain22 = "flashplayeractivex.info" nocase
        $domain23 = "freewula.strangled.net" nocase
        $domain24 = "fssprus.dns04.com" nocase
        $domain25 = "ftp.microft.dynssl.com" nocase
        $domain26 = "gamepoer7.com" nocase
        $domain27 = "gigabitdate.com" nocase
        $domain28 = "goon.oldvideo.longmusic.com" nocase
        $domain29 = "journal.itsaol.com" nocase
        $domain30 = "js.journal.itsaol.com" nocase
        $domain31 = "lck.gigabitdate.com" nocase
        $domain32 = "lib.hostareas.com" nocase
        $domain33 = "loge.otzo.com" nocase
        $domain34 = "mail.playdr2.com" nocase
        $domain35 = "mcafee-update.com" nocase
        $domain36 = "miche.justdied.com" nocase
        $domain37 = "micro.dns04.com" nocase
        $domain38 = "microft.dynssl.com" nocase
        $domain39 = "mktoon.ftp1.biz" nocase
        $domain40 = "news.flashplayeractivex.info" nocase
        $domain41 = "noon.dns04.com" nocase
        $domain42 = "ns2.gamepoer7.com" nocase
        $domain43 = "ns9.mcafee-update.com" nocase
        $domain44 = "oldvideo.longmusic.com" nocase
        $domain45 = "omgod.org" nocase
        $domain46 = "playdr2.com" nocase
        $domain47 = "pop.playdr2.com" nocase
        $domain48 = "powergame.0077.x24hr.com" nocase
        $domain49 = "q34ewrd.youdontcare.com" nocase
        $domain50 = "reportsearch.dynamic-dns.net" nocase
        $domain51 = "rt.ftp1.biz" nocase
        $domain52 = "ruclient.dns04.com" nocase
        $domain53 = "safer.ddns.us" nocase
        $domain54 = "sdo.microft.dynssl.com" nocase
        $domain55 = "search.microft.dynssl.com" nocase
        $domain56 = "serviechelp.changeip.us" nocase
        $domain57 = "shareddocs.microft.dynssl.com" nocase
        $domain58 = "smsreport.microft.dynssl.com" nocase
        $domain59 = "speedtest.reportsearch.dynamic-dns.net" nocase
        $domain60 = "sprfilet.microft.dynssl.com" nocase
        $domain61 = "srcier0wqesj1.microft.dynssl.com" nocase
        $domain62 = "srv.xxxy.biz" nocase
        $domain63 = "ssl.gigabitdate.com" nocase
        $domain64 = "sslvpn.microft.dynssl.com" nocase
        $domain65 = "staticd.dynamic-dns.net" nocase
        $domain66 = "stmspeedtest.reportsearch.dynamic-dns.net" nocase
        $domain67 = "szuunet.strangled.net" nocase
        $domain68 = "tombstone.kozow.com" nocase
        $domain69 = "toogasd.www.oldvideo.longmusic.com" nocase
        $domain70 = "toon.mrbasic.com" nocase
        $domain71 = "update.flashplayeractivex.info" nocase
        $domain72 = "w.asd3.as.amazon-corp.wikaba.com" nocase
        $domain73 = "web.miscrosaft.com" nocase
        $domain74 = "webdocsshare.microft.dynssl.com" nocase
        $domain75 = "werwesf.dynamic-dns.net" nocase
        $domain76 = "wserver1.microft.dynssl.com" nocase
        $domain77 = "wwa1we.wbew.amazon-corp.wikaba.com" nocase
        $domain78 = "ybcps4.freeddns.org" nocase
        $ip79 = "101.37.16.125"
        $ip80 = "103.101.178.152"
        $ip81 = "120.78.127.189"
        $ip82 = "121.89.210.144"
        $ip83 = "154.211.161.161"
        $ip84 = "154.85.48.108"
        $ip85 = "170.178.190.213"
        $ip86 = "192.225.226.123"
        $ip87 = "192.225.226.217"
        $ip88 = "192.225.226.218"
        $ip89 = "207.148.121.88"
        $ip90 = "45.77.16.91"
        $ip91 = "47.108.89.169"

    condition:
        any of them
}

rule APT_STEALTHFALCON {
    meta:
        description = "Indicators associated with APT STEALTHFALCON"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "adhostingcache.com" nocase
        $domain1 = "adlinkmetric.com" nocase
        $domain2 = "adlinkmetrics.com" nocase
        $domain3 = "adobereaderupdater.com" nocase
        $domain4 = "airlineadverts.com" nocase
        $domain5 = "akamai-host-network.com" nocase
        $domain6 = "akamai-hosting-network.com" nocase
        $domain7 = "akamaicachecdn.com" nocase
        $domain8 = "akamaicloud.net" nocase
        $domain9 = "akamaicss.com" nocase
        $domain10 = "akamaihostcdn.net" nocase
        $domain11 = "akamaiwebcache.com" nocase
        $domain12 = "appleimagecache.com" nocase
        $domain13 = "bestairlinepricetags.com" nocase
        $domain14 = "burst-media.com" nocase
        $domain15 = "cachecontent.com" nocase
        $domain16 = "cdn-logichosting.com" nocase
        $domain17 = "cdnimagescache.com" nocase
        $domain18 = "chromeupdater.com" nocase
        $domain19 = "clickstatistic.com" nocase
        $domain20 = "cloudburstcdn.net" nocase
        $domain21 = "cloudburstercdn.net" nocase
        $domain22 = "cloudimagecdn.com" nocase
        $domain23 = "cloudimagehosters.com" nocase
        $domain24 = "contenthosts.com" nocase
        $domain25 = "contenthosts.net" nocase
        $domain26 = "cyclingonlineshop.com" nocase
        $domain27 = "dnsclienthelper.com" nocase
        $domain28 = "dnsclientresolver.com" nocase
        $domain29 = "domainimagehost.com" nocase
        $domain30 = "dotnetupdatechecker.com" nocase
        $domain31 = "dotnetupdates.com" nocase
        $domain32 = "downloadessays.net" nocase
        $domain33 = "dropboxsyncservice.com" nocase
        $domain34 = "edgecacheimagehosting.com" nocase
        $domain35 = "electricalweb.org" nocase
        $domain36 = "fastfilebackup.com" nocase
        $domain37 = "fasttravelclearance.com" nocase
        $domain38 = "flashplayersupdates.com" nocase
        $domain39 = "flashplayerupdater.com" nocase
        $domain40 = "footballtimes.info" nocase
        $domain41 = "healthherofit.com" nocase
        $domain42 = "iesafebrowsingcache.com" nocase
        $domain43 = "iesaferbrowsingcache.com" nocase
        $domain44 = "incapsulawebcache.com" nocase
        $domain45 = "javaupdatecache.com" nocase
        $domain46 = "javaupdatersvc.com" nocase
        $domain47 = "javaupdatescache.com" nocase
        $domain48 = "javaupdatesvc.com" nocase
        $domain49 = "limelightimagecache.com" nocase
        $domain50 = "livewebcache.com" nocase
        $domain51 = "luxuryfitnesslabs.com" nocase
        $domain52 = "media-providers.net" nocase
        $domain53 = "mediacachecdn.com" nocase
        $domain54 = "mediacachecdn.net" nocase
        $domain55 = "mediacloudsolution.com" nocase
        $domain56 = "mediacloudsolutions.net" nocase
        $domain57 = "mediaimagecache.com" nocase
        $domain58 = "mediaproviders.net" nocase
        $domain59 = "ministrynewschannel.com" nocase
        $domain60 = "ministrynewsinfo.com" nocase
        $domain61 = "msofficesso.com" nocase
        $domain62 = "msofficeupdates.com" nocase
        $domain63 = "mswindowsupdater.com" nocase
        $domain64 = "netassistcache.com" nocase
        $domain65 = "netcloudcdn.com" nocase
        $domain66 = "optimizedimghosting.com" nocase
        $domain67 = "optimizercache.com" nocase
        $domain68 = "oraclejavaupdate.com" nocase
        $domain69 = "oraclejavaupdater.com" nocase
        $domain70 = "purvoyage.com" nocase
        $domain71 = "radiotimesignal.com" nocase
        $domain72 = "rapidlinkhit.com" nocase
        $domain73 = "roundedbullets.com" nocase
        $domain74 = "safeadspace.com" nocase
        $domain75 = "safeadvertimgs.com" nocase
        $domain76 = "simpleadbanners.com" nocase
        $domain77 = "summerartcamp.net" nocase
        $domain78 = "tinyimagehosting.com" nocase
        $domain79 = "upnpdiscover.org" nocase
        $domain80 = "vegetableportfolio.com" nocase
        $domain81 = "webanalyticstats.com" nocase
        $domain82 = "wincertificateupdater.com" nocase
        $domain83 = "winconnectors.com" nocase
        $domain84 = "windefenderupdater.com" nocase
        $domain85 = "windowsconnector.com" nocase
        $domain86 = "windowsdefenderupdater.com" nocase
        $domain87 = "windowsearchcache.com" nocase
        $domain88 = "windowshealthcheck.com" nocase
        $domain89 = "windowspatchmanager.com" nocase
        $domain90 = "windowssearchcache.com" nocase
        $domain91 = "windowsupdatecache.com" nocase
        $domain92 = "windowsupdatescache.com" nocase
        $domain93 = "worryfreetransport.com" nocase

    condition:
        any of them
}

rule APT_STOLENPENCIL {
    meta:
        description = "Indicators associated with APT STOLENPENCIL"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "babyshark, kimjongrat"

    strings:
        $domain0 = "bizsonet.ayar.biz" nocase
        $domain1 = "bizsonet.com" nocase
        $domain2 = "client-message.com" nocase
        $domain3 = "client-screenfonts.com" nocase
        $domain4 = "docsdriver.com" nocase
        $domain5 = "grsvps.com" nocase
        $domain6 = "itservicedesk.org" nocase
        $domain7 = "pqexport.com" nocase
        $domain8 = "scaurri.com" nocase
        $domain9 = "secozco.com" nocase
        $domain10 = "sharedriver.pw" nocase
        $domain11 = "sharedriver.us" nocase
        $domain12 = "tempdomain8899.com" nocase
        $domain13 = "world-paper.net" nocase
        $domain14 = "zwfaxi.com" nocase

    condition:
        any of them
}

rule APT_STONEDRILL {
    meta:
        description = "Indicators associated with APT STONEDRILL"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "eservice.com" nocase
        $domain1 = "securityupdated.com" nocase

    condition:
        any of them
}

rule APT_STONEFLY {
    meta:
        description = "Indicators associated with APT STONEFLY"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-45, apt45, onyx sleet"

    strings:
        $domain0 = "bluedragon.com" nocase
        $domain1 = "cyancow.com" nocase
        $domain2 = "phpick.com" nocase
        $domain3 = "semiconductboard.com" nocase
        $domain4 = "tecnojournals.com" nocase
        $domain5 = "trollbydefault.com" nocase
        $ip6 = "216.120.201.112"
        $ip7 = "51.81.168.157"

    condition:
        any of them
}

rule APT_STRONGPITY {
    meta:
        description = "Indicators associated with APT STRONGPITY"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-41, promethium, strongpity"

    strings:
        $domain0 = "apn-state-upd2.com" nocase
        $domain1 = "app-mx3-delivery.com" nocase
        $domain2 = "applicationrepo.com" nocase
        $domain3 = "apt5-secure3-state.com" nocase
        $domain4 = "cdn12-web-security.com" nocase
        $domain5 = "cdn2-state-upd.com" nocase
        $domain6 = "cdn2-svr-state.com" nocase
        $domain7 = "cdn4-rxe3-map.com" nocase
        $domain8 = "cerulearc.com" nocase
        $domain9 = "dutchvideochatting.com" nocase
        $domain10 = "edicupd002.com" nocase
        $domain11 = "fairgowingo.com" nocase
        $domain12 = "fileaccesscontrol.com" nocase
        $domain13 = "filedocumentmanager.com" nocase
        $domain14 = "findingpcdrivers.com" nocase
        $domain15 = "ftp.mynetenergy.com" nocase
        $domain16 = "hardwareoption.com" nocase
        $domain17 = "hierarchicalfiles.com" nocase
        $domain18 = "hostoperationsystems.com" nocase
        $domain19 = "hotpatches.net" nocase
        $domain20 = "hybirdcloudreportingsoftware.com" nocase
        $domain21 = "informationserviceslab.com" nocase
        $domain22 = "inodeapplicationserver.com" nocase
        $domain23 = "intagrefedcircuitchip.com" nocase
        $domain24 = "javaplugin-update.com" nocase
        $domain25 = "lurkingnet.com" nocase
        $domain26 = "mailtransfersagents.com" nocase
        $domain27 = "mentiononecommon.com" nocase
        $domain28 = "ms-cdn-88.com" nocase
        $domain29 = "ms-health-monitor.com" nocase
        $domain30 = "ms-sys-security.com" nocase
        $domain31 = "ms21-app3-upload.com" nocase
        $domain32 = "ms6-upload-serv3.com" nocase
        $domain33 = "mx-upd2-cdn-state.com" nocase
        $domain34 = "myrappid.com" nocase
        $domain35 = "mytoshba.com" nocase
        $domain36 = "networkmanagemersolutions.com" nocase
        $domain37 = "networksoftwaresegment.com" nocase
        $domain38 = "node1-cdn-network.com" nocase
        $domain39 = "oem-sec4-mx32.com" nocase
        $domain40 = "pinkturtle.me" nocase
        $domain41 = "protectapplication.com" nocase
        $domain42 = "pulmonyarea.com" nocase
        $domain43 = "ralrab.com" nocase
        $domain44 = "record-fords.cerulearc.com" nocase
        $domain45 = "remoteaaddressconnect.com" nocase
        $domain46 = "repositoryupdating.com" nocase
        $domain47 = "requiredvision.com" nocase
        $domain48 = "resolutionplatform.com" nocase
        $domain49 = "selectednewfile.com" nocase
        $domain50 = "serv3-app-system4.com" nocase
        $domain51 = "sessionprotocol.com" nocase
        $domain52 = "srv-cdn3-system.com" nocase
        $domain53 = "srv5-upd51-mx3-sec22.com" nocase
        $domain54 = "srv601.ddns.net" nocase
        $domain55 = "srv602.ddns.net" nocase
        $domain56 = "state-awe3-apt.com" nocase
        $domain57 = "svnservices.com" nocase
        $domain58 = "svr-sec2-system.com" nocase
        $domain59 = "sys4-upload2-srv.com" nocase
        $domain60 = "syse-update-app4.com" nocase
        $domain61 = "system6-mxe-ups3.com" nocase
        $domain62 = "transfermychoice.com" nocase
        $domain63 = "transferprotocolpolicy.com" nocase
        $domain64 = "true-crypte.website" nocase
        $domain65 = "truecrypte.org" nocase
        $domain66 = "upd-ncx4-server.com" nocase
        $domain67 = "upd-network-ms2.com" nocase
        $domain68 = "upd-secure-srv1.com" nocase
        $domain69 = "upd2-app-state.com" nocase
        $domain70 = "upd3-srv-system-app.com" nocase
        $domain71 = "upd32-secure-serv4.com" nocase
        $domain72 = "upd56-state3-cdn7-mx8.com" nocase
        $domain73 = "updatesync.com" nocase
        $domain74 = "updserv-east-cdn3.com" nocase
        $domain75 = "upn-sec3-msd.com" nocase
        $domain76 = "uppertrainingtool.com" nocase
        $domain77 = "windriversupport.com" nocase
        $ip78 = "193.235.207.60"

    condition:
        any of them
}

rule APT_STUXNET {
    meta:
        description = "Indicators associated with APT STUXNET"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "mypremierfutbol.com" nocase
        $domain1 = "todaysfutbol.com" nocase

    condition:
        any of them
}

rule APT_TA2101 {
    meta:
        description = "Indicators associated with APT TA2101"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "conbase.top" nocase
        $domain1 = "uspsdelivery-service.com" nocase

    condition:
        any of them
}

rule APT_TA240524 {
    meta:
        description = "Indicators associated with APT TA240524"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "Actor240524, ABCloader, ABCsync"

    strings:
        $ip0 = "185.23.253.143"

    condition:
        any of them
}

rule APT_TA410 {
    meta:
        description = "Indicators associated with APT TA410"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "FlowCloud, LookBack, LookingFrog"

    strings:
        $domain0 = "a.bigbluedc.com" nocase
        $domain1 = "asce.email" nocase
        $domain2 = "bigbluedc.com" nocase
        $domain3 = "cahe.microsofts.com" nocase
        $domain4 = "daveengineer.com" nocase
        $domain5 = "dlaxpcmghd.com" nocase
        $domain6 = "energysemi.com" nocase
        $domain7 = "eset-sync.com" nocase
        $domain8 = "ffca.caibi379.com" nocase
        $domain9 = "nsfwgo.com" nocase
        $domain10 = "powersafetraining.net" nocase
        $domain11 = "powersafetrainings.org" nocase
        $domain12 = "s.eset-sync.com" nocase
        $domain13 = "smtp.nsfwgo.com" nocase
        $domain14 = "translateupdate.com" nocase
        $domain15 = "update.translateupdate.com" nocase
        $ip16 = "103.139.2.93"
        $ip17 = "188.131.233.27"
        $ip18 = "188.131.233.27"

    condition:
        any of them
}

rule APT_TA416 {
    meta:
        description = "Indicators associated with APT TA416"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "upespr.com" nocase
        $domain1 = "zyber-i.com" nocase
        $ip2 = "103.107.104.19"
        $ip3 = "103.107.104.19"
        $ip4 = "103.107.104.19"
        $ip5 = "107.167.64.4"
        $ip6 = "45.154.14.235"
        $ip7 = "45.248.87.162"
        $ip8 = "69.90.184.125"
        $ip9 = "92.118.188.78"

    condition:
        any of them
}

rule APT_TA428 {
    meta:
        description = "Indicators associated with APT TA428"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "nccTrojan, phantomnet, smanager"

    strings:
        $domain0 = "aircraft.tsagagaar.com" nocase
        $domain1 = "aiwqi.aurobindos.com" nocase
        $domain2 = "atlas.golianbooks.com" nocase
        $domain3 = "atob.kommesantor.com" nocase
        $domain4 = "aurobindos.com" nocase
        $domain5 = "beijingspring.niccenter.net" nocase
        $domain6 = "bloomberg.mefound.com" nocase
        $domain7 = "bloomberg.ns02.biz" nocase
        $domain8 = "cniitiic.com" nocase
        $domain9 = "coms.documentmeda.com" nocase
        $domain10 = "custom.songuulcomiss.com" nocase
        $domain11 = "darknightcloud.com" nocase
        $domain12 = "defensysminck.net" nocase
        $domain13 = "dm.golianbooks.com" nocase
        $domain14 = "doc.redstrpela.net" nocase
        $domain15 = "documentmeda.com" nocase
        $domain16 = "dog.darknightcloud.com" nocase
        $domain17 = "dotomater.club" nocase
        $domain18 = "ecustoms-mn.com" nocase
        $domain19 = "eye.darknightcloud.com" nocase
        $domain20 = "f1news.vzglagtime.net" nocase
        $domain21 = "fax.internnetionfax.com" nocase
        $domain22 = "foudation.sdelanasnou.com" nocase
        $domain23 = "freenow.chickenkiller.com" nocase
        $domain24 = "fuji1.aurobindos.com" nocase
        $domain25 = "gazar.ecustoms-mn.com" nocase
        $domain26 = "go.vegispaceshop.org" nocase
        $domain27 = "gogonews.organiccrap.com" nocase
        $domain28 = "golianbooks.com" nocase
        $domain29 = "govi-altai.ecustoms-mn.com" nocase
        $domain30 = "home.sysclearprom.space" nocase
        $domain31 = "idfnv.net" nocase
        $domain32 = "info.ntcprotek.com" nocase
        $domain33 = "internnetionfax.com" nocase
        $domain34 = "kino.redstrpela.net" nocase
        $domain35 = "kommesantor.com" nocase
        $domain36 = "krseoul93.idfnv.net" nocase
        $domain37 = "morgoclass.com" nocase
        $domain38 = "mtanews.vzglagtime.net" nocase
        $domain39 = "news-click.net" nocase
        $domain40 = "news.niiriip.com" nocase
        $domain41 = "news.vzglagtime.net" nocase
        $domain42 = "nicblainfo.net" nocase
        $domain43 = "niigem.olloo-news.com" nocase
        $domain44 = "niiriip.com" nocase
        $domain45 = "nmcustoms.https443.org" nocase
        $domain46 = "nppnavigator.net" nocase
        $domain47 = "ns02.ns02.us" nocase
        $domain48 = "ns28.ntcprotek.com" nocase
        $domain49 = "ntcprotek.com" nocase
        $domain50 = "nubia.tsagagaar.com" nocase
        $domain51 = "office365.blogdns.com" nocase
        $domain52 = "olloo-news.com" nocase
        $domain53 = "oolnewsmongol.ddns.info" nocase
        $domain54 = "org.senyulinjiu.xyz" nocase
        $domain55 = "penmuseum.niccenter.net" nocase
        $domain56 = "redstrpela.net" nocase
        $domain57 = "rps.news-click.net" nocase
        $domain58 = "sdelanasnou.com" nocase
        $domain59 = "senyulinjiu.xyz" nocase
        $domain60 = "server.dotomater.club" nocase
        $domain61 = "skype.swingfished.com" nocase
        $domain62 = "snow.swingfished.com" nocase
        $domain63 = "songuulcomiss.com" nocase
        $domain64 = "swingfished.com" nocase
        $domain65 = "sysclearprom.space" nocase
        $domain66 = "tbelement.niccenter.net" nocase
        $domain67 = "tech.songuulcomiss.com" nocase
        $domain68 = "term.internnetionfax.com" nocase
        $domain69 = "thedalailama90.niccenter.net" nocase
        $domain70 = "tick.sysclearprom.space" nocase
        $domain71 = "tsagagaar.com" nocase
        $domain72 = "vgca.homeunix.org" nocase
        $domain73 = "video.nicblainfo.net" nocase
        $domain74 = "vpkimplus.com" nocase
        $domain75 = "vpknpomashnic.com" nocase
        $domain76 = "vzglagtime.net" nocase
        $domain77 = "www1.dotomater.club" nocase
        $domain78 = "www1.nppnavigator.net" nocase
        $domain79 = "www2.defensysminck.net" nocase
        $domain80 = "www2.morgoclass.com" nocase
        $domain81 = "www2.sdelanasnou.com" nocase
        $domain82 = "www2.vpknpomashnic.com" nocase
        $domain83 = "www3.vpkimplus.com" nocase
        $domain84 = "www7.vpkimplus.com" nocase
        $domain85 = "yjdjcnm.cniitiic.com" nocase
        $ip86 = "103.249.87.72"
        $ip87 = "104.234.15.90"
        $ip88 = "185.82.218.40"
        $ip89 = "185.82.218.40"
        $ip90 = "185.82.219.182"
        $ip91 = "185.82.219.182"
        $ip92 = "217.69.8.255"
        $ip93 = "45.154.12.93"
        $ip94 = "45.63.27.162"
        $ip95 = "45.76.210.68"
        $ip96 = "45.76.210.68"
        $ip97 = "45.77.129.213"
        $ip98 = "95.179.131.29"

    condition:
        any of them
}

rule APT_TA555 {
    meta:
        description = "Indicators associated with APT TA555"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "194.36.188.132"

    condition:
        any of them
}

rule APT_TA5918 {
    meta:
        description = "Indicators associated with APT TA5918"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "uat-5918, uat-7237"

    strings:
        $domain0 = "cvbbonwxtgvc3isfqfc52cwzja0kvuqd.lambda-url.ap-northeast-1.on.aws" nocase

    condition:
        any of them
}

rule APT_TAG22 {
    meta:
        description = "Indicators associated with APT TAG22"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "tag-22"

    strings:
        $domain0 = "microsoftd.tk" nocase
        $domain1 = "wikimedia.vip" nocase
        $domain2 = "windowshostnamehost.club" nocase

    condition:
        any of them
}

rule APT_TAG28 {
    meta:
        description = "Indicators associated with APT TAG28"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "UIDAI"

    strings:
        $domain0 = "admin.samuelblog.xyz" nocase
        $domain1 = "date.samuelblog.info" nocase
        $domain2 = "db1.samuelblog.me" nocase
        $domain3 = "db1.samuelblog.site" nocase
        $domain4 = "samuelblog.info" nocase
        $domain5 = "samuelblog.me" nocase
        $domain6 = "samuelblog.site" nocase
        $domain7 = "samuelblog.website" nocase
        $domain8 = "samuelblog.xyz" nocase

    condition:
        any of them
}

rule APT_TAJMAHAL {
    meta:
        description = "Indicators associated with APT TAJMAHAL"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "rahasn.akamake.net" nocase
        $domain1 = "rahasn.homewealth.biz" nocase
        $domain2 = "rahasn.webhop.org" nocase

    condition:
        any of them
}

rule APT_TEALKURMA {
    meta:
        description = "Indicators associated with APT TEALKURMA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "snappytcp"

    strings:
        $domain0 = "23be.xtechsupport.org" nocase
        $domain1 = "ai-connector.goldchekin.com" nocase
        $domain2 = "ai-connector.splendor.org" nocase
        $domain3 = "ai-connector.splendos.org" nocase
        $domain4 = "al-marsad.co" nocase
        $domain5 = "alarabiyaa.online" nocase
        $domain6 = "alhurra.online" nocase
        $domain7 = "anfturkce.news" nocase
        $domain8 = "aws.systemctl.network" nocase
        $domain9 = "boord.info" nocase
        $domain10 = "caglayandergisi.net" nocase
        $domain11 = "cn.sslname.com" nocase
        $domain12 = "dhcp.systemctl.network" nocase
        $domain13 = "eth0.secrsys.net" nocase
        $domain14 = "exp-al-marsad.co" nocase
        $domain15 = "forward.boord.info" nocase
        $domain16 = "infohaber.net" nocase
        $domain17 = "lo0.systemctl.network" nocase
        $domain18 = "loading-website.net" nocase
        $domain19 = "netssh.net" nocase
        $domain20 = "nmcbcd.live" nocase
        $domain21 = "nuceciwan.news" nocase
        $domain22 = "querryfiles.com" nocase
        $domain23 = "secrsys.net" nocase
        $domain24 = "serverssl.net" nocase
        $domain25 = "solhaber.info" nocase
        $domain26 = "solhaber.news" nocase
        $domain27 = "systemctl.network" nocase
        $domain28 = "ud.ybcd.tech" nocase
        $domain29 = "update.qnetau.net" nocase
        $domain30 = "upt.mcsoft.org" nocase
        $domain31 = "xtechsupport.org" nocase
        $domain32 = "ybcd.tech" nocase
        $ip33 = "62.115.255.163"

    condition:
        any of them
}

rule APT_TELEBOTS {
    meta:
        description = "Indicators associated with APT TELEBOTS"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "esetsmart.org" nocase
        $domain1 = "um10eset.net" nocase

    condition:
        any of them
}

rule APT_TEMPPERISCOPE {
    meta:
        description = "Indicators associated with APT TEMPPERISCOPE"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "chemscalere.com" nocase
        $domain1 = "mlcdailynews.com" nocase
        $domain2 = "partyforumseasia.com" nocase
        $domain3 = "scsnewstoday.com" nocase
        $domain4 = "thyssenkrupp-marinesystems.org" nocase

    condition:
        any of them
}

rule APT_TEMPTINGCEDAR {
    meta:
        description = "Indicators associated with APT TEMPTINGCEDAR"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "arab-chat.site" nocase
        $domain1 = "arab-download.com" nocase
        $domain2 = "chat-messenger.site" nocase
        $domain3 = "chat-world.site" nocase
        $domain4 = "free-apps.us" nocase
        $domain5 = "gserv.mobi" nocase
        $domain6 = "kikstore.net" nocase
        $domain7 = "network-lab.info" nocase
        $domain8 = "onlineclub.info" nocase

    condition:
        any of them
}

rule APT_TENGYUNSNAKE {
    meta:
        description = "Indicators associated with APT TENGYUNSNAKE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-61, apt-q-122"

    strings:
        $domain0 = "a0w.herokuapp.com" nocase
        $domain1 = "a0x.herokuapp.com" nocase
        $domain2 = "en-db.herokuapp.com" nocase
        $domain3 = "en-docs.herokuapp.com" nocase
        $domain4 = "en-localhost.herokuapp.com" nocase
        $domain5 = "en-office365updatescente.herokuapp.com" nocase
        $domain6 = "fcdn.pythonanywhere.com" nocase
        $domain7 = "il1.000webhostapp.com" nocase
        $domain8 = "jl3.000webhostapp.com" nocase
        $domain9 = "media.randreports.org" nocase
        $domain10 = "o-s.herokuapp.com" nocase
        $domain11 = "os.herokuapp.com" nocase
        $domain12 = "p-v.herokuapp.com" nocase
        $domain13 = "p92.herokuapp.com" nocase
        $domain14 = "pn0.herokuapp.com" nocase
        $domain15 = "ps9.000webhostapp.com" nocase
        $domain16 = "sysupdate.pythonanywhere.com" nocase
        $domain17 = "w0m.herokuapp.com" nocase

    condition:
        any of them
}

rule APT_THEWIZARDS {
    meta:
        description = "Indicators associated with APT THEWIZARDS"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "darknights, dknife, spellbinder"

    strings:
        $domain0 = "assetsqq.com" nocase
        $domain1 = "mkdmcdn.com" nocase
        $domain2 = "ssl-dns.com" nocase
        $domain3 = "vv.ssl-dns.com" nocase
        $ip4 = "110.185.104.180"
        $ip5 = "110.92.64.177"
        $ip6 = "117.175.185.81"
        $ip7 = "43.132.205.118"
        $ip8 = "43.155.62.54"
        $ip9 = "47.238.107.83"
        $ip10 = "47.93.54.134"
        $ip11 = "47.93.54.134"
        $ip12 = "47.93.54.134"
        $ip13 = "49.89.41.187"
        $ip14 = "49.89.41.187"
        $ip15 = "49.89.41.187"
        $ip16 = "89.195.5.18"

    condition:
        any of them
}

rule APT_TIBET {
    meta:
        description = "Indicators associated with APT TIBET"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "1.test.3322.org.cn" nocase
        $domain1 = "123ewqasdcxz.xicp.net" nocase
        $domain2 = "2.test.3322.org.cn" nocase
        $domain3 = "3.test.3322.org.cn" nocase
        $domain4 = "4.test.3322.org.cn" nocase
        $domain5 = "airjaldinet.ml" nocase
        $domain6 = "antmoving.online" nocase
        $domain7 = "beemail.online" nocase
        $domain8 = "bf.mk" nocase
        $domain9 = "browserservice.zzux.com" nocase
        $domain10 = "client-user-id.com" nocase
        $domain11 = "cta-tibet.com" nocase
        $domain12 = "ctmail.dns-dns.com" nocase
        $domain13 = "dalailama.online" nocase
        $domain14 = "designer.dynamic-dns.net" nocase
        $domain15 = "energy-mail.org" nocase
        $domain16 = "getadobeflashdownloader.proxydns.com" nocase
        $domain17 = "gmail.isooncloud.com" nocase
        $domain18 = "gmailapp.me" nocase
        $domain19 = "hoop-america.oicp.net" nocase
        $domain20 = "hotmal1.com" nocase
        $domain21 = "hy.micrsofts.com" nocase
        $domain22 = "in-tibet.net" nocase
        $domain23 = "install.ddns.info" nocase
        $domain24 = "ip.micrsofts.com" nocase
        $domain25 = "izelense.com" nocase
        $domain26 = "loginwebmailnic.dynssl.com" nocase
        $domain27 = "ly.micorsofts.net" nocase
        $domain28 = "mail-tibet.net" nocase
        $domain29 = "mailanalysis.services" nocase
        $domain30 = "mailcontactanalysis.online" nocase
        $domain31 = "mailnotes.online" nocase
        $domain32 = "micorsofts.net" nocase
        $domain33 = "micrsofts.com" nocase
        $domain34 = "mon7am.000webhostapp.com" nocase
        $domain35 = "mon7am.tk" nocase
        $domain36 = "msap.services" nocase
        $domain37 = "news.cmitcsubs.tk" nocase
        $domain38 = "polarismail.services" nocase
        $domain39 = "rf.mk" nocase
        $domain40 = "root20system20macosxdriver.serveusers.com" nocase
        $domain41 = "roots.dynamic-dns.net" nocase
        $domain42 = "tibet-office.com" nocase
        $domain43 = "tibetoffice.in" nocase
        $domain44 = "ubntrooters.serveuser.com" nocase
        $domain45 = "walkingnote.online" nocase
        $domain46 = "windows-report.com" nocase
        $domain47 = "xdx.hotmal1.com" nocase
        $ip48 = "43.251.16.87"
        $ip49 = "45.76.149.154"
        $ip50 = "66.42.58.59"

    condition:
        any of them
}

rule APT_TICK {
    meta:
        description = "Indicators associated with APT TICK"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "amamihanahana.com" nocase
        $domain1 = "englandprevail.com" nocase
        $domain2 = "han-game.com" nocase
        $domain3 = "kot.gogoblog.net" nocase
        $domain4 = "memsbay.com" nocase
        $domain5 = "menu.han-game.com" nocase
        $domain6 = "menu.rakutenline.com" nocase
        $domain7 = "menu.sa-guard.com" nocase
        $domain8 = "mssql.waterglue.org" nocase
        $domain9 = "oracle.eneygylakes.com" nocase
        $domain10 = "poi.cydisk.net" nocase
        $domain11 = "pre.englandprevail.com" nocase
        $domain12 = "rakutenline.com" nocase
        $domain13 = "rbb.gol-unkai4.com" nocase
        $domain14 = "rp.thumbbay.com" nocase
        $domain15 = "sa-guard.com" nocase
        $domain16 = "slientship.com" nocase
        $domain17 = "travelasist.com" nocase
        $domain18 = "update.saranmall.com" nocase

    condition:
        any of them
}

rule APT_TIDRONE {
    meta:
        description = "Indicators associated with APT TIDRONE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "clntend, cxclnt, tidrone"

    strings:
        $domain0 = "auto-update.microsoftsvc.com" nocase
        $domain1 = "bestadll.fghytr.com" nocase
        $domain2 = "client.wns.windowswns.com" nocase
        $domain3 = "eupractic.s3.ap-east-1.amazonaws.com" nocase
        $domain4 = "fghytr.com" nocase
        $domain5 = "hp.kt168.org" nocase
        $domain6 = "microsoftsvc.com" nocase
        $domain7 = "onmondayr.s3.ap-east-1.amazonaws.com" nocase
        $domain8 = "server.microsoftsvc.com" nocase
        $domain9 = "service.symantecsecuritycloud.com" nocase
        $domain10 = "symantecsecuritycloud.com" nocase
        $domain11 = "time.vmwaresync.com" nocase
        $domain12 = "totting.s3.ap-east-1.amazonaws.com" nocase
        $domain13 = "tpckcapital.top" nocase
        $domain14 = "update.microsoftsvc.com" nocase
        $domain15 = "upgrade.microsoftsvc.com" nocase
        $domain16 = "uppaycn.com" nocase
        $domain17 = "vmwaresync.com" nocase
        $domain18 = "windowswns.com" nocase
        $domain19 = "wns.windowswns.com" nocase
        $domain20 = "wot.tpckcapital.top" nocase
        $ip21 = "154.23.184.30"

    condition:
        any of them
}

rule APT_TINYSCOUTS {
    meta:
        description = "Indicators associated with APT TINYSCOUTS"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "oldgremlin, tinyfluff"

    strings:
        $domain0 = "a3c65c.org" nocase
        $domain1 = "broken-poetry-de86.nscimupf.workers.dev" nocase
        $domain2 = "calm-night-6067.bhrcaoqf.workers.dev" nocase
        $domain3 = "ccdn.microsoftdocs.workers.dev" nocase
        $domain4 = "curly-sound-d93e.ygrhxogxiogc.workers.dev" nocase
        $domain5 = "eccbc8.com" nocase
        $domain6 = "hello.tyvbxdobr0.workers.dev" nocase
        $domain7 = "ksdkpwpfrtyvbxdobr1.tiyvbxdobr1.workers.dev" nocase
        $domain8 = "ksdkpwprtyvbxdobr0.tyvbxdobr0.workers.dev" nocase
        $domain9 = "late-salad-2839.yriqwzjskbbg.workers.dev" nocase
        $domain10 = "mirfinance.org" nocase
        $domain11 = "noisy-cell-7d07.poecdjusb.workers.dev" nocase
        $domain12 = "ns1.a3c65c.org" nocase
        $domain13 = "ns1.eccbc8.com" nocase
        $domain14 = "ns2.a3c65c.org" nocase
        $domain15 = "ns2.eccbc8.com" nocase
        $domain16 = "ns3.a3c65c.org" nocase
        $domain17 = "ns3.eccbc8.com" nocase
        $domain18 = "ns4.a3c65c.org" nocase
        $domain19 = "ns4.eccbc8.com" nocase
        $domain20 = "odd-thunder-c853.tkbizulvc.workers.dev" nocase
        $domain21 = "old-mud-23cb.tkbizulvc.workers.dev" nocase
        $domain22 = "rbcholding.press" nocase
        $domain23 = "rough-grass-45e9.poecdjusb.workers.dev" nocase
        $domain24 = "wispy-fire-1da3.nscimupf.workers.dev" nocase
        $domain25 = "wispy-surf-fabd.bhrcaoqf.workers.dev" nocase
        $ip26 = "161.35.41.9"
        $ip27 = "46.101.113.161"

    condition:
        any of them
}

rule APT_TODDYCAT {
    meta:
        description = "Indicators associated with APT TODDYCAT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "ad.fopingu.com" nocase
        $domain1 = "admit.pkigoscorp.com" nocase
        $domain2 = "backend.rtmcsync.com" nocase
        $domain3 = "cdn.pkigoscorp.com" nocase
        $domain4 = "cert.qform3d.in" nocase
        $domain5 = "certexvpn.com" nocase
        $domain6 = "cyberguard.certexvpn.com" nocase
        $domain7 = "eaq.machineaccountquota.com" nocase
        $domain8 = "eohsdnsaaojrhnqo.windowshost.us" nocase
        $domain9 = "fopingu.com" nocase
        $domain10 = "gist.gitbusercontent.com" nocase
        $domain11 = "git.gitbusercontent.com" nocase
        $domain12 = "gitbusercontent.com" nocase
        $domain13 = "githubdd.workers.dev" nocase
        $domain14 = "idp.pkigoscorp.com" nocase
        $domain15 = "imap.774b884034c450b.com" nocase
        $domain16 = "machineaccountquota.com" nocase
        $domain17 = "mfeagents.workers.dev" nocase
        $domain18 = "ns01.nayatel.orinafz.com" nocase
        $domain19 = "pic.rtmcsync.com" nocase
        $domain20 = "pkigoscorp.com" nocase
        $domain21 = "proxy.rtmcsync.com" nocase
        $domain22 = "qaq2.machineaccountquota.com" nocase
        $domain23 = "qform3d.in" nocase
        $domain24 = "raw.gitbusercontent.com" nocase
        $domain25 = "rtmcsync.com" nocase
        $domain26 = "solitary-dawn-61af.mfeagents.workers.dev" nocase
        $domain27 = "sslvpn.pkigoscorp.com" nocase
        $domain28 = "update.certexvpn.com" nocase
        $ip29 = "139.180.145.121"

    condition:
        any of them
}

rule APT_TORTOISESHELL {
    meta:
        description = "Indicators associated with APT TORTOISESHELL"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "imperial kitten, crimson sandstorm, ta456"

    strings:
        $domain0 = "1st-smtp2go.email" nocase
        $domain1 = "2nd-smtp2go.email" nocase
        $domain2 = "3rd-smtp2go.email" nocase
        $domain3 = "4th-smtp2go.email" nocase
        $domain4 = "accounts.cam" nocase
        $domain5 = "activesessions.me" nocase
        $domain6 = "adobes.software" nocase
        $domain7 = "alhds.net" nocase
        $domain8 = "apppure.cf" nocase
        $domain9 = "bahri.site" nocase
        $domain10 = "bbcnews.email" nocase
        $domain11 = "bitly.cam" nocase
        $domain12 = "biturl.cx" nocase
        $domain13 = "brdcst.email" nocase
        $domain14 = "careeronestop.site" nocase
        $domain15 = "cc-security-inc.email" nocase
        $domain16 = "ccsecurity-mail-inc.email" nocase
        $domain17 = "ccsecurity-mail-inc.services" nocase
        $domain18 = "citymyworkday.com" nocase
        $domain19 = "cityofberkeley.support" nocase
        $domain20 = "cnbcnews.email" nocase
        $domain21 = "cnnnews.global" nocase
        $domain22 = "codejquery-ui.com" nocase
        $domain23 = "com-account-challenge.email" nocase
        $domain24 = "com-signin-v2.email" nocase
        $domain25 = "comlogin.online" nocase
        $domain26 = "comlogin.services" nocase
        $domain27 = "copyleft.today" nocase
        $domain28 = "crisiswatchsupport.shop" nocase
        $domain29 = "datacatch.xyz" nocase
        $domain30 = "dayzim.org" nocase
        $domain31 = "dh135.world" nocase
        $domain32 = "dollrealdoll.com" nocase
        $domain33 = "dollrealdoll.online" nocase
        $domain34 = "entrust.work" nocase
        $domain35 = "erictrumpfundation.com" nocase
        $domain36 = "facebookservices.gq" nocase
        $domain37 = "fblogin.me" nocase
        $domain38 = "fileblade.ga" nocase
        $domain39 = "findcareersatusbofa.com" nocase
        $domain40 = "fiservcareers.com" nocase
        $domain41 = "goodreads.rest" nocase
        $domain42 = "googl.club" nocase
        $domain43 = "gropinggo.com" nocase
        $domain44 = "hex6mak5z98nubb9vpd6t36cydkncfci9im872qx6hjci2egx8irq3qyt9pj.online" nocase
        $domain45 = "hike.studio" nocase
        $domain46 = "hiremilitaryheroes.com" nocase
        $domain47 = "hosted-microsoft.com" nocase
        $domain48 = "iemail.today" nocase
        $domain49 = "incognito.today" nocase
        $domain50 = "infoga.cam" nocase
        $domain51 = "iqtel.org" nocase
        $domain52 = "irtreporter.com" nocase
        $domain53 = "itiee.life" nocase
        $domain54 = "itieee.life" nocase
        $domain55 = "jessicamcgill.life" nocase
        $domain56 = "jqueryui-code.com" nocase
        $domain57 = "jumhuria.com" nocase
        $domain58 = "kartick.net" nocase
        $domain59 = "kaspersky.team" nocase
        $domain60 = "linkgen.me" nocase
        $domain61 = "linksbit.com" nocase
        $domain62 = "linq.ink" nocase
        $domain63 = "liveleak.cam" nocase
        $domain64 = "liveuamap.live" nocase
        $domain65 = "lockheedmartinjobs.us" nocase
        $domain66 = "loginaccount.email" nocase
        $domain67 = "logonexchangeonline.com" nocase
        $domain68 = "logonmicrosoftonline.com" nocase
        $domain69 = "lskjirn.life" nocase
        $domain70 = "mail2go.live" nocase
        $domain71 = "mail2go.online" nocase
        $domain72 = "mail2u.live" nocase
        $domain73 = "mailaccountlive.email" nocase
        $domain74 = "mailaccountlive.support" nocase
        $domain75 = "mailpublisher.live" nocase
        $domain76 = "mails.center" nocase
        $domain77 = "metacafe.live" nocase
        $domain78 = "micorsoftonilne.com" nocase
        $domain79 = "micorsoftonline.website" nocase
        $domain80 = "micorsoftonline.xyz" nocase
        $domain81 = "microsoftoffice.systems" nocase
        $domain82 = "microsoftonilne.cloud" nocase
        $domain83 = "mispace.cam" nocase
        $domain84 = "msol.live" nocase
        $domain85 = "msonline.live" nocase
        $domain86 = "mssecurityaccount.online" nocase
        $domain87 = "mydomainxyz.xyz" nocase
        $domain88 = "news-smtp2go.email" nocase
        $domain89 = "newsl.ink" nocase
        $domain90 = "noreplay.email" nocase
        $domain91 = "novafile.tk" nocase
        $domain92 = "onpointcorp.co" nocase
        $domain93 = "outlook-services.com" nocase
        $domain94 = "outlookservices.live" nocase
        $domain95 = "outlookservices.me" nocase
        $domain96 = "outube.live" nocase
        $domain97 = "pic-shareonline.com" nocase
        $domain98 = "pixlr.live" nocase
        $domain99 = "post-jquery.com" nocase

    condition:
        any of them
}

rule APT_TRANSPARENTTRIBE {
    meta:
        description = "Indicators associated with APT TRANSPARENTTRIBE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-56, sidecopy, falseflag"

    strings:
        $domain0 = "01411.club" nocase
        $domain1 = "130t.xyz" nocase
        $domain2 = "1ov.shop" nocase
        $domain3 = "1s1.accesscam.org" nocase
        $domain4 = "2.digipay.us.cc" nocase
        $domain5 = "2co.shop" nocase
        $domain6 = "2ndline.cfd" nocase
        $domain7 = "34667.fun" nocase
        $domain8 = "37-221-64-202.cprapid.com" nocase
        $domain9 = "37-221-64-252.cprapid.com" nocase
        $domain10 = "376zbaqsnigt.com" nocase
        $domain11 = "3a4p8gq8bojwn.xyz" nocase
        $domain12 = "414.camdvr.org" nocase
        $domain13 = "415.mywire.org" nocase
        $domain14 = "419.theworkpc.com" nocase
        $domain15 = "43-228-125-28.cprapid.com" nocase
        $domain16 = "5-135-125-106.cinfuserver.com" nocase
        $domain17 = "56184.fun" nocase
        $domain18 = "5gsewa.cyou" nocase
        $domain19 = "5zbm0.cfd" nocase
        $domain20 = "66xq2.top" nocase
        $domain21 = "6jxbmkpe.torontobotdns.com" nocase
        $domain22 = "76767.icu" nocase
        $domain23 = "78990.fun" nocase
        $domain24 = "7thcpcupdates.info" nocase
        $domain25 = "873013.xyz" nocase
        $domain26 = "88c.34667.fun" nocase
        $domain27 = "89204.fun" nocase
        $domain28 = "8a.monitorondomainlintgt.store" nocase
        $domain29 = "8fold.space" nocase
        $domain30 = "8ln62.cfd" nocase
        $domain31 = "8thpaycomission.cloud" nocase
        $domain32 = "8tqxpf27.torontobotdns.com" nocase
        $domain33 = "903.78990.fun" nocase
        $domain34 = "9123.89204.fun" nocase
        $domain35 = "9882aa1216.autos" nocase
        $domain36 = "999game.website" nocase
        $domain37 = "9gi02.cfd" nocase
        $domain38 = "9ydygorig3l7z.xyz" nocase
        $domain39 = "9z.monitorondomainwintgt2.store" nocase
        $domain40 = "a.erforias.cam" nocase
        $domain41 = "aa.76767.icu" nocase
        $domain42 = "aadharpor.xyz" nocase
        $domain43 = "aadharsewa.site" nocase
        $domain44 = "aadperson.xyz" nocase
        $domain45 = "aaloochaat.com" nocase
        $domain46 = "aboutcase.nl" nocase
        $domain47 = "ac.76767.icu" nocase
        $domain48 = "accinfo.live" nocase
        $domain49 = "account-recovery.com" nocase
        $domain50 = "account.migration.jkpolice.gov.in.mgovcloud.de" nocase
        $domain51 = "accountmail.in" nocase
        $domain52 = "accounts-migration.mgovcloud.de" nocase
        $domain53 = "accounts.mgovcloud.de" nocase
        $domain54 = "accounts.mgovcloud.in.cloudshare.digital" nocase
        $domain55 = "accounts.mgovcloud.in.departmentofdefence.live" nocase
        $domain56 = "accounts.mgovcloud.in.indiagov.support" nocase
        $domain57 = "accounts.mgovcloud.in.storagecloud.download" nocase
        $domain58 = "accounts.mgovcloud.in.virtualeoffice.cloud" nocase
        $domain59 = "accountsinfo.site" nocase
        $domain60 = "accountsmgovcloud.in.campindia.xyz" nocase
        $domain61 = "acemastersat.com" nocase
        $domain62 = "acescricket.com" nocase
        $domain63 = "achaoblog.org" nocase
        $domain64 = "acmarketsapp.com" nocase
        $domain65 = "acml-ai.com" nocase
        $domain66 = "acml-ltd.com" nocase
        $domain67 = "acml-vip.com" nocase
        $domain68 = "acml-web.com" nocase
        $domain69 = "ad.caselist.in" nocase
        $domain70 = "ad2.admart.tv" nocase
        $domain71 = "adiptv.duckdns.org" nocase
        $domain72 = "admin-br.in" nocase
        $domain73 = "admin-dept.in" nocase
        $domain74 = "admin-desk.in" nocase
        $domain75 = "admin-mcas-df.ms" nocase
        $domain76 = "adminbr.in" nocase
        $domain77 = "admincell.in" nocase
        $domain78 = "admincoord.in" nocase
        $domain79 = "admindept.in" nocase
        $domain80 = "admindesk.in" nocase
        $domain81 = "adminsec.in" nocase
        $domain82 = "advanceservice.in" nocase
        $domain83 = "advanceservice.in.103-160-106-28.cpanel.site" nocase
        $domain84 = "adverify.in" nocase
        $domain85 = "advising-receipts.com" nocase
        $domain86 = "advisor-resort.com" nocase
        $domain87 = "aerivoro.com" nocase
        $domain88 = "aeroclubofindia.co.in" nocase
        $domain89 = "afgcloud7.com" nocase
        $domain90 = "afghannewsnetwork.com" nocase
        $domain91 = "aiabcd.xyz" nocase
        $domain92 = "aiapplication.chat" nocase
        $domain93 = "aidfix.help" nocase
        $domain94 = "aidline.help" nocase
        $domain95 = "aidplus.help" nocase
        $domain96 = "aidsol.help" nocase
        $domain97 = "ail-govs.icu" nocase
        $domain98 = "airforce-update.net" nocase
        $domain99 = "aise-your-voice.sbs" nocase
        $ip100 = "101.99.92.182"
        $ip101 = "101.99.92.182"
        $ip102 = "101.99.92.182"
        $ip103 = "101.99.94.109"
        $ip104 = "101.99.94.109"
        $ip105 = "103.2.232.82"
        $ip106 = "103.231.254.55"
        $ip107 = "104.129.27.14"
        $ip108 = "104.129.27.14"
        $ip109 = "104.129.27.14"
        $ip110 = "104.129.27.14"
        $ip111 = "104.129.27.14"
        $ip112 = "104.129.42.102"
        $ip113 = "104.129.42.102"
        $ip114 = "104.129.42.102"
        $ip115 = "104.129.42.102"
        $ip116 = "104.129.42.102"
        $ip117 = "104.144.198.105"
        $ip118 = "104.144.198.105"
        $ip119 = "104.144.198.105"
        $ip120 = "104.144.198.105"
        $ip121 = "104.144.198.105"
        $ip122 = "104.168.48.210"
        $ip123 = "104.168.48.210"
        $ip124 = "104.168.48.210"
        $ip125 = "104.168.48.210"
        $ip126 = "104.168.48.210"
        $ip127 = "104.223.106.8"
        $ip128 = "104.227.97.53"
        $ip129 = "107.150.18.166"
        $ip130 = "107.172.76.170"
        $ip131 = "107.173.204.38"
        $ip132 = "107.173.204.38"
        $ip133 = "107.175.1.103"
        $ip134 = "107.175.1.103"
        $ip135 = "107.175.1.103"
        $ip136 = "107.175.1.103"
        $ip137 = "107.175.1.103"
        $ip138 = "107.175.64.209"
        $ip139 = "107.175.64.251"
        $ip140 = "107.175.95.107"
        $ip141 = "109.236.85.16"
        $ip142 = "119.157.27.213"
        $ip143 = "122.166.149.57"
        $ip144 = "129.154.249.114"
        $ip145 = "129.227.206.99"
        $ip146 = "134.119.181.142"
        $ip147 = "134.119.181.142"
        $ip148 = "134.119.181.15"
        $ip149 = "134.119.181.15"

    condition:
        any of them
}

rule APT_TRIANGULATION {
    meta:
        description = "Indicators associated with APT TRIANGULATION"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "addatamarket.net" nocase
        $domain1 = "ans7tv.net" nocase
        $domain2 = "anstv.net" nocase
        $domain3 = "backuprabbit.com" nocase
        $domain4 = "businessvideonews.com" nocase
        $domain5 = "cloudsponcer.com" nocase
        $domain6 = "datamarketplace.net" nocase
        $domain7 = "growthtransport.com" nocase
        $domain8 = "mobilegamerstats.com" nocase
        $domain9 = "snoweeanalytics.com" nocase
        $domain10 = "tagclick-cdn.com" nocase
        $domain11 = "topographyupdates.com" nocase
        $domain12 = "unlimitedteacup.com" nocase
        $domain13 = "virtuallaughing.com" nocase
        $domain14 = "web-trackers.com" nocase

    condition:
        any of them
}

rule APT_TURLA {
    meta:
        description = "Indicators associated with APT TURLA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "waterbug, snake, whitebear"

    strings:
        $domain0 = "61paris.fr" nocase
        $domain1 = "academyawards.effers.com" nocase
        $domain2 = "accessdest.strangled.net" nocase
        $domain3 = "adgf.am" nocase
        $domain4 = "adstore.twilightparadox.com" nocase
        $domain5 = "agony.compress.to" nocase
        $domain6 = "api.softwareupdatenews.com" nocase
        $domain7 = "archive-articles.linkpc.net" nocase
        $domain8 = "arctic-zone.bbsindex.com" nocase
        $domain9 = "arinas.tk" nocase
        $domain10 = "auberdine.etowns.net" nocase
        $domain11 = "av.master.dns-cloud.net" nocase
        $domain12 = "avmaster.dns-cloud.net" nocase
        $domain13 = "badget.ignorelist.com" nocase
        $domain14 = "baltdefcol.webredirect.org" nocase
        $domain15 = "bedrost.com" nocase
        $domain16 = "bestfunc.slyip.net" nocase
        $domain17 = "bigpen.ga" nocase
        $domain18 = "blackerror.ignorelist.com" nocase
        $domain19 = "booking.etowns.org" nocase
        $domain20 = "booking.strangled.net" nocase
        $domain21 = "bookstore.strangled.net" nocase
        $domain22 = "branter.tk" nocase
        $domain23 = "bronerg.tk" nocase
        $domain24 = "bug.ignorelist.com" nocase
        $domain25 = "buy-new-car.com" nocase
        $domain26 = "caduff-sa.chjeepcarlease.com" nocase
        $domain27 = "canal1zac1a.onrender.com" nocase
        $domain28 = "carleasingguru.com" nocase
        $domain29 = "cars-online.zapto.org" nocase
        $domain30 = "cdn.datacenterate.com" nocase
        $domain31 = "celestyna.tk" nocase
        $domain32 = "ceremon.2waky.com" nocase
        $domain33 = "cheapflights.etowns.net" nocase
        $domain34 = "chinafood.chickenkiller.com" nocase
        $domain35 = "chjeepcarlease.com" nocase
        $domain36 = "climbent.mooo.com" nocase
        $domain37 = "codewizard.ml" nocase
        $domain38 = "coldriver.strangled.net" nocase
        $domain39 = "communityeu.xp3.biz" nocase
        $domain40 = "connectotels.net" nocase
        $domain41 = "crusider.tk" nocase
        $domain42 = "cyberazov.com" nocase
        $domain43 = "cyberazov.tk" nocase
        $domain44 = "d3hdbjtb1686tn.cloudfront.net" nocase
        $domain45 = "da.anythinktech.com" nocase
        $domain46 = "datacenterate.com" nocase
        $domain47 = "davilta.tk" nocase
        $domain48 = "dellservice.publicvm.com" nocase
        $domain49 = "deme.ml" nocase
        $domain50 = "developarea.mooo.com" nocase
        $domain51 = "dixito.ml" nocase
        $domain52 = "downtown.crabdance.com" nocase
        $domain53 = "driverx86-adobe.onrender.com" nocase
        $domain54 = "dropbox12.com" nocase
        $domain55 = "dsme.info" nocase
        $domain56 = "dubaiexpo2020.cf" nocase
        $domain57 = "duke6.tk" nocase
        $domain58 = "dzerl.com" nocase
        $domain59 = "easport-news.publicvm.com" nocase
        $domain60 = "easports.3d-game.com" nocase
        $domain61 = "ebay-global.publicvm.com" nocase
        $domain62 = "ekrn.ydns.eu" nocase
        $domain63 = "elizabi.tk" nocase
        $domain64 = "en.footballcharge.us" nocase
        $domain65 = "eset.ydns.eu" nocase
        $domain66 = "esetcloud.com" nocase
        $domain67 = "ethdns.mywire.org" nocase
        $domain68 = "eu-sciffi.99k.org" nocase
        $domain69 = "euassociate.6te.net" nocase
        $domain70 = "euland.freevar.com" nocase
        $domain71 = "eunews-online.zapto.org" nocase
        $domain72 = "eurovision.chickenkiller.com" nocase
        $domain73 = "excelupdates.org" nocase
        $domain74 = "f0304768.xsph.ru" nocase
        $domain75 = "fifa-rules.25u.com" nocase
        $domain76 = "fleetwood.tk" nocase
        $domain77 = "foods.jkub.com" nocase
        $domain78 = "footballcharge.us" nocase
        $domain79 = "forum.4dq.com" nocase
        $domain80 = "forum.acmetoy.com" nocase
        $domain81 = "forum.sytes.net" nocase
        $domain82 = "forumgeek.zzux.com" nocase
        $domain83 = "franceonline.sytes.net" nocase
        $domain84 = "freeutils.3utilities.com" nocase
        $domain85 = "gallop.mefound.com" nocase
        $domain86 = "goldenroade.strangled.net" nocase
        $domain87 = "google-ai-labs-it.onrender.com" nocase
        $domain88 = "greateplan.ocry.com" nocase
        $domain89 = "greece-travel.servepics.com" nocase
        $domain90 = "hanagram.jpthefinetreats.com" nocase
        $domain91 = "health-everyday.faqserv.com" nocase
        $domain92 = "highcolumn.webredirect.org" nocase
        $domain93 = "highhills.ignorelist.com" nocase
        $domain94 = "hockey-news.servehttp.com" nocase
        $domain95 = "hofa.tk" nocase
        $domain96 = "hostelhotels.net" nocase
        $domain97 = "hotspot.accesscam.org" nocase
        $domain98 = "hunvin.tk" nocase
        $domain99 = "ies.inquirer.com.ph" nocase
        $ip100 = "103.136.43.65"
        $ip101 = "103.143.40.60"
        $ip102 = "103.143.40.91"
        $ip103 = "103.30.76.194"
        $ip104 = "104.167.16.42"
        $ip105 = "134.209.222.206"
        $ip106 = "154.53.42.194"
        $ip107 = "185.126.255.132"
        $ip108 = "185.253.116.122"
        $ip109 = "194.36.190.17"
        $ip110 = "205.186.64.197"
        $ip111 = "38.180.173.194"
        $ip112 = "45.64.186.26"
        $ip113 = "45.89.107.77"
        $ip114 = "46.17.45.93"
        $ip115 = "5.252.176.22"
        $ip116 = "85.222.235.156"

    condition:
        any of them
}

rule APT_TVRMS {
    meta:
        description = "Indicators associated with APT TVRMS"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "barinoh9.beget.tech" nocase
        $domain1 = "barinovbb.had.su" nocase
        $domain2 = "buhuchetooo.ru" nocase
        $domain3 = "document-buh.com" nocase
        $domain4 = "micorsoft.info" nocase
        $domain5 = "mts2015stm.myjino.ru" nocase
        $domain6 = "papaninili.temp.swtest.ru" nocase
        $domain7 = "rosatomgov.ru" nocase

    condition:
        any of them
}

rule APT_TWISTEDPANDA {
    meta:
        description = "Indicators associated with APT TWISTEDPANDA"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "elliotterusties.com" nocase
        $domain1 = "img.elliotterusties.com" nocase
        $domain2 = "microtreely.com" nocase
        $domain3 = "miniboxmail.com" nocase
        $domain4 = "minzdravros.com" nocase

    condition:
        any of them
}

rule APT_UNC1151 {
    meta:
        description = "Indicators associated with APT UNC1151"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "RADIOSTAR, VIDEOKILLER, HALFSHELL"

    strings:
        $domain0 = "a1si.icu" nocase
        $domain1 = "a3ufz.xsjdsb.icu" nocase
        $domain2 = "account-inbox.online" nocase
        $domain3 = "account-login.top" nocase
        $domain4 = "account-noreply.space" nocase
        $domain5 = "account-passports.top" nocase
        $domain6 = "account.no-replay-notification.ga" nocase
        $domain7 = "accounts-facebook.com-pastas.top" nocase
        $domain8 = "accounts-gmail.com-check.online" nocase
        $domain9 = "accounts-gmail.com-login.space" nocase
        $domain10 = "accounts-gmail.com-pastas.top" nocase
        $domain11 = "accounts-group.com-pastas.top" nocase
        $domain12 = "accounts-inbox.ml" nocase
        $domain13 = "accounts-login.top" nocase
        $domain14 = "accounts-mail.site" nocase
        $domain15 = "accounts-passport.top" nocase
        $domain16 = "accounts-secure.com-firewall.online" nocase
        $domain17 = "accounts-support.com-account.website" nocase
        $domain18 = "accounts-support.net-account.space" nocase
        $domain19 = "accounts-telekom.online" nocase
        $domain20 = "accounts-ukr.net-account.space" nocase
        $domain21 = "accounts-ukr.net-verification.online" nocase
        $domain22 = "accounts-verification.net-account.space" nocase
        $domain23 = "accounts-verify.space" nocase
        $domain24 = "accounts.safe-mail.space" nocase
        $domain25 = "accounts.secure-ua.site" nocase
        $domain26 = "accounts.secure-ua.website" nocase
        $domain27 = "accounts.verify-email.space" nocase
        $domain28 = "accountsverify.top" nocase
        $domain29 = "acount-pasport.site" nocase
        $domain30 = "acount-passport.site" nocase
        $domain31 = "acounts.net-verification.online" nocase
        $domain32 = "advancedaisolutionsforeveryone.a1si.icu" nocase
        $domain33 = "aff-gos.top" nocase
        $domain34 = "agelessinvesting.xyz" nocase
        $domain35 = "ais-gos.top" nocase
        $domain36 = "akademia-mil.space" nocase
        $domain37 = "alertapp.icu" nocase
        $domain38 = "alerteddatalistsclients.alertapp.icu" nocase
        $domain39 = "alexavegas.icu" nocase
        $domain40 = "algsat.icu" nocase
        $domain41 = "all-ukraine.top" nocase
        $domain42 = "alls-gos.top" nocase
        $domain43 = "americandeliriumsociety.shop" nocase
        $domain44 = "ams-gos.top" nocase
        $domain45 = "ao-opros.top" nocase
        $domain46 = "api.passport-yandex.ru" nocase
        $domain47 = "aplikacje.ron-mil.space" nocase
        $domain48 = "attachment-storage-asset-static.needbinding.icu" nocase
        $domain49 = "authorization-inbox.site" nocase
        $domain50 = "awa-opros.top" nocase
        $domain51 = "aws-opros.top" nocase
        $domain52 = "backstagemerch.shop" nocase
        $domain53 = "beez-gos.top" nocase
        $domain54 = "bel-oprosov.top" nocase
        $domain55 = "belaru-opros.top" nocase
        $domain56 = "bell-gos.club" nocase
        $domain57 = "besh-opros.top" nocase
        $domain58 = "best-seller.lavanille.buzz" nocase
        $domain59 = "bezpieczenstwo-danych.website" nocase
        $domain60 = "bezpieczenstwo.wp-pl.eu" nocase
        $domain61 = "bhwbehb.wecwe.com" nocase
        $domain62 = "big-uah.club" nocase
        $domain63 = "bigmir-net.site" nocase
        $domain64 = "bigmir.space" nocase
        $domain65 = "bild-gos.club" nocase
        $domain66 = "bind-gos.cc" nocase
        $domain67 = "biz-gos.top" nocase
        $domain68 = "blic-opros.top" nocase
        $domain69 = "bokinteria.pl-kontrola-bezpieczenstwa.space" nocase
        $domain70 = "bokinteria.weryfikacja-konta.pw" nocase
        $domain71 = "book-happy.needbinding.icu" nocase
        $domain72 = "boom-gos.club" nocase
        $domain73 = "bourns.space" nocase
        $domain74 = "bryndonovan.shop" nocase
        $domain75 = "bui-gos.top" nocase
        $domain76 = "canada-deposit-gst.com" nocase
        $domain77 = "canada-gst-deposit.com" nocase
        $domain78 = "carpetmarker.pw" nocase
        $domain79 = "cgdirector.icu" nocase
        $domain80 = "chaptercheats.shop" nocase
        $domain81 = "cheap-gos.club" nocase
        $domain82 = "chis-gos.top" nocase
        $domain83 = "ci-uah.xyz" nocase
        $domain84 = "clairedeco.shop" nocase
        $domain85 = "cloud-security.ggpht.ml" nocase
        $domain86 = "com-account.website" nocase
        $domain87 = "com-firewall.online" nocase
        $domain88 = "com-login.space" nocase
        $domain89 = "com-pastas.top" nocase
        $domain90 = "com-validate.site" nocase
        $domain91 = "com-validation.top" nocase
        $domain92 = "com-verificate.top" nocase
        $domain93 = "com-verification.online" nocase
        $domain94 = "com-verification.top" nocase
        $domain95 = "com-verify.site" nocase
        $domain96 = "command-email.online" nocase
        $domain97 = "compensatia.top" nocase
        $domain98 = "compensation-ukr.com" nocase
        $domain99 = "compensations-ukrain.bar" nocase
        $ip100 = "109.237.111.251"
        $ip101 = "185.175.158.27"
        $ip102 = "88.99.104.179"
        $ip103 = "88.99.132.118"
        $ip104 = "91.142.77.157"

    condition:
        any of them
}

rule APT_UNC215 {
    meta:
        description = "Indicators associated with APT UNC215"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "103.59.144.183"
        $ip1 = "103.79.78.48"
        $ip2 = "139.59.81.253"
        $ip3 = "141.164.52.232"
        $ip4 = "159.89.168.83"
        $ip5 = "34.65.151.250"
        $ip6 = "47.75.49.32"
        $ip7 = "85.204.74.143"
        $ip8 = "89.35.178.105"

    condition:
        any of them
}

rule APT_UNC2190 {
    meta:
        description = "Indicators associated with APT UNC2190"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "54bb47h, sabbath"

    strings:
        $domain0 = "4bb47h5qu4k7l4d7v5ix3i6ak6elysn3net4by4ihmvrhu7cvbskoqd.onion" nocase
        $domain1 = "54bb47h.blog" nocase
        $domain2 = "54bb47h5qu4k7l4d7v5ix3i6ak6elysn3net4by4ihmvrhu7cvbskoqd.onion" nocase
        $domain3 = "aequuira1aedeezais5i.probes.space" nocase
        $domain4 = "aimee0febai5phoht2ti.probes.website" nocase
        $domain5 = "cofeeloveers.com" nocase
        $domain6 = "datatransferdc.com" nocase
        $domain7 = "doratir.com" nocase
        $domain8 = "farhadl.com" nocase
        $domain9 = "frankir.com" nocase
        $domain10 = "gordonzon.com" nocase
        $domain11 = "greentuks.com" nocase
        $domain12 = "helpgoldr.com" nocase
        $domain13 = "jeithe7eijeefohch3qu.probes.site" nocase
        $domain14 = "markettc.biz" nocase
        $domain15 = "probes.site" nocase
        $domain16 = "probes.space" nocase
        $domain17 = "probes.website" nocase
        $domain18 = "securingyourpc.com" nocase
        $domain19 = "security4themasses.com" nocase
        $domain20 = "tinysidney.com" nocase
        $ip21 = "45.141.84.182"
        $ip22 = "45.146.166.24"
        $ip23 = "45.147.230.137"
        $ip24 = "45.147.230.221"
        $ip25 = "45.79.55.129"

    condition:
        any of them
}

rule APT_UNC2447 {
    meta:
        description = "Indicators associated with APT UNC2447"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "celomito.com" nocase
        $domain1 = "cosarm.com" nocase
        $domain2 = "feticost.com" nocase
        $domain3 = "portalcos.com" nocase

    condition:
        any of them
}

rule APT_UNC2452 {
    meta:
        description = "Indicators associated with APT UNC2452"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "raindrop, solorigate, sunburst"

    strings:
        $domain0 = "1cloudserver.com" nocase
        $domain1 = "40ort.750.credit" nocase
        $domain2 = "6a57jk2ba1d9keg15cbg.appsync-api.eu-west-1.avsvmcloud.com" nocase
        $domain3 = "74d6b7b2.app.giftbox4u.com" nocase
        $domain4 = "7sbvaemscs0mc925tb99.appsync-api.us-west-2.avsvmcloud.com" nocase
        $domain5 = "actualityworld.com" nocase
        $domain6 = "adagio.betterworldshopping.com" nocase
        $domain7 = "admirer.onehourcfo.com" nocase
        $domain8 = "adsprofitnetwork.com" nocase
        $domain9 = "aimsecurity.net" nocase
        $domain10 = "alertmeter.info" nocase
        $domain11 = "apexwebtech.com" nocase
        $domain12 = "appsprovider.com" nocase
        $domain13 = "appsync-api.eu-west-1.avsvmcloud.com" nocase
        $domain14 = "appsync-api.us-east-1.avsvmcloud.com" nocase
        $domain15 = "appsync-api.us-east-2.avsvmcloud.com" nocase
        $domain16 = "appsync-api.us-west-2.avsvmcloud.com" nocase
        $domain17 = "armrvrholo.com" nocase
        $domain18 = "assetdata.net" nocase
        $domain19 = "autonetonline.com" nocase
        $domain20 = "avsvmcloud.com" nocase
        $domain21 = "bacionera.top" nocase
        $domain22 = "backup.awarfaregaming.com" nocase
        $domain23 = "bfilmnews.com" nocase
        $domain24 = "bigdataanalysts.com" nocase
        $domain25 = "bigtopweb.com" nocase
        $domain26 = "bmlor.750.credit" nocase
        $domain27 = "builder.visionarybusiness.net" nocase
        $domain28 = "camogit.com" nocase
        $domain29 = "cdnappservice.firebaseio.com" nocase
        $domain30 = "champions.gdtc.org" nocase
        $domain31 = "cityloss.com" nocase
        $domain32 = "coloradospringsroofing.info" nocase
        $domain33 = "combat.strategyforgood.com" nocase
        $domain34 = "computerrepublic.com" nocase
        $domain35 = "content.pcmsar.net" nocase
        $domain36 = "context.septemberyears.org" nocase
        $domain37 = "crochetnews.com" nocase
        $domain38 = "cross-checking.com" nocase
        $domain39 = "d3ser9acyt7cdp.cloudfront.net" nocase
        $domain40 = "daddy.stlouisdemoday.com" nocase
        $domain41 = "dailydews.com" nocase
        $domain42 = "databasegalore.com" nocase
        $domain43 = "dataplane.theyardservice.com" nocase
        $domain44 = "datatidy.com" nocase
        $domain45 = "datazr.com" nocase
        $domain46 = "defender5.coachwithak.com" nocase
        $domain47 = "deftsecurity.com" nocase
        $domain48 = "diamondglobalnetwork.com" nocase
        $domain49 = "digitalcollege.org" nocase
        $domain50 = "digitalphotohub.com" nocase
        $domain51 = "doggroomingnews.com" nocase
        $domain52 = "dom-news.com" nocase
        $domain53 = "domainingdirectory.com" nocase
        $domain54 = "ebbcloud.com" nocase
        $domain55 = "ebookstorelive.com" nocase
        $domain56 = "email.theyardservice.com" nocase
        $domain57 = "emergencystreet.com" nocase
        $domain58 = "enpport.com" nocase
        $domain59 = "ernesttheskoolie.com" nocase
        $domain60 = "ervsystem.com" nocase
        $domain61 = "eventbrite-com-default-rtdb.firebaseio.com" nocase
        $domain62 = "eyetechltd.com" nocase
        $domain63 = "fanta.swofficefurniture.com" nocase
        $domain64 = "financialmarket.org" nocase
        $domain65 = "flowers.netplusplans.com" nocase
        $domain66 = "flowers.thegardnerco.com" nocase
        $domain67 = "fqtel.com" nocase
        $domain68 = "freescanonline.com" nocase
        $domain69 = "freespace.givingprofits.net" nocase
        $domain70 = "galatinonews.com" nocase
        $domain71 = "gallery.wineadam.com" nocase
        $domain72 = "gallerycenter.org" nocase
        $domain73 = "gdbcloud.com" nocase
        $domain74 = "giftbox4u.com" nocase
        $domain75 = "globalnetworkissues.com" nocase
        $domain76 = "globalsection.org" nocase
        $domain77 = "globesoftwares.com" nocase
        $domain78 = "gnadptech.com" nocase
        $domain79 = "gq1h856599gqh538acqn.appsync-api.us-west-2.avsvmcloud.com" nocase
        $domain80 = "graphicscodex.net" nocase
        $domain81 = "group3.pulsedesigngroup.us" nocase
        $domain82 = "hanproud.com" nocase
        $domain83 = "highdatabase.com" nocase
        $domain84 = "holescontracting.com" nocase
        $domain85 = "humanitarian-forum-default-rtdb.firebaseio.com" nocase
        $domain86 = "ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud.com" nocase
        $domain87 = "incomeupdate.com" nocase
        $domain88 = "inferno.bigpurposebigimpact.com" nocase
        $domain89 = "infinitysoftwares.com" nocase
        $domain90 = "inspirer.cartsandmowers.com" nocase
        $domain91 = "ioxmesh.com" nocase
        $domain92 = "ipadsreview.org" nocase
        $domain93 = "jenkins.findfwd.com" nocase
        $domain94 = "joke.webproduct.info" nocase
        $domain95 = "joomla.lifepath.site" nocase
        $domain96 = "k5kcubuassl3alrf7gm3.appsync-api.eu-west-1.avsvmcloud.com" nocase
        $domain97 = "kaceloj.com" nocase
        $domain98 = "kefas.id" nocase
        $domain99 = "kirute.com" nocase
        $ip100 = "179.43.141.188"
        $ip101 = "179.43.141.188"
        $ip102 = "179.43.141.188"
        $ip103 = "185.189.151.182"
        $ip104 = "185.225.69.69"
        $ip105 = "216.243.39.167"
        $ip106 = "5.75.159.186"
        $ip107 = "5.75.159.186"
        $ip108 = "5.75.159.186"
        $ip109 = "5.75.159.186"
        $ip110 = "5.75.159.186"
        $ip111 = "5.75.159.186"
        $ip112 = "91.219.239.43"
        $ip113 = "91.219.239.54"
        $ip114 = "91.219.239.54"
        $ip115 = "98.225.248.37"

    condition:
        any of them
}

rule APT_UNC2465 {
    meta:
        description = "Indicators associated with APT UNC2465"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "smokedham"

    strings:
        $domain0 = "08f0.proxy-edge-c5f.workers.dev" nocase
        $domain1 = "10bet.space" nocase
        $domain2 = "12.workbencn.com" nocase
        $domain3 = "178.159.43.206.sslip.io" nocase
        $domain4 = "1r.rvtoolsed.com" nocase
        $domain5 = "1s.rvtoolsai.com" nocase
        $domain6 = "1v.rvtoollsa.com" nocase
        $domain7 = "1v.rvtootsad.com" nocase
        $domain8 = "1yeralti.com" nocase
        $domain9 = "20.rvtoolsaq.com" nocase
        $domain10 = "20.rvtoolse.info" nocase
        $domain11 = "20.rvtoolsme.com" nocase
        $domain12 = "21.rvtoolsen.com" nocase
        $domain13 = "22.rvtoolsik.com" nocase
        $domain14 = "24.rvtoolis.info" nocase
        $domain15 = "24.rvtoolsgo.com" nocase
        $domain16 = "27.rvtoolsax.com" nocase
        $domain17 = "2a.rvtoolso.info" nocase
        $domain18 = "2b.rvtoolsit.com" nocase
        $domain19 = "2j.rvtoolsup.com" nocase
        $domain20 = "2w.s3abrowser.com" nocase
        $domain21 = "3g.s3brovvser.com" nocase
        $domain22 = "3p.workbenche.com" nocase
        $domain23 = "40.workbencse.com" nocase
        $domain24 = "45perhour.org" nocase
        $domain25 = "4l.rvtoolslab.com" nocase
        $domain26 = "4t.rvtoolsacs.com" nocase
        $domain27 = "54.rvtoolsone.com" nocase
        $domain28 = "58.rvtoolsmax.com" nocase
        $domain29 = "5b.rvtoolsbox.com" nocase
        $domain30 = "5n.rvtoolsrun.com" nocase
        $domain31 = "7stories.sbs" nocase
        $domain32 = "91movs.com" nocase
        $domain33 = "9xstream.live" nocase
        $domain34 = "aapanel116864.hostkey.in" nocase
        $domain35 = "aapanel34768.hostkey.in" nocase
        $domain36 = "abstractest-hydroski.site" nocase
        $domain37 = "academytradeai.com" nocase
        $domain38 = "accoumtsclienntsarea.us" nocase
        $domain39 = "acquasicuras.com" nocase
        $domain40 = "actbluecs.com" nocase
        $domain41 = "actblues.net" nocase
        $domain42 = "adionetjrei.shop" nocase
        $domain43 = "admin.rvtoolacs.online" nocase
        $domain44 = "adrilex.digital" nocase
        $domain45 = "aexnp.com" nocase
        $domain46 = "afd-esign.info" nocase
        $domain47 = "afeherbopenuk.com" nocase
        $domain48 = "agora-mesmo.com" nocase
        $domain49 = "agronomywork.info" nocase
        $domain50 = "aiadvancedreasoning.com" nocase
        $domain51 = "aiagentanalytics.com" nocase
        $domain52 = "aiagentledger.com" nocase
        $domain53 = "aialgocamp.com" nocase
        $domain54 = "aialgocore.com" nocase
        $domain55 = "aialgodrive.com" nocase
        $domain56 = "aialgoflow.com" nocase
        $domain57 = "aialgofusion.com" nocase
        $domain58 = "aialgohash.com" nocase
        $domain59 = "aialgorithmforge.com" nocase
        $domain60 = "aialgorithmicforge.com" nocase
        $domain61 = "aialgorithmicpath.com" nocase
        $domain62 = "aialgosense.com" nocase
        $domain63 = "aialgosphere.com" nocase
        $domain64 = "aianalyticengine.com" nocase
        $domain65 = "aianalyticmesh.com" nocase
        $domain66 = "aiautomationframework.com" nocase
        $domain67 = "aiautonomycore.com" nocase
        $domain68 = "aibigdatamap.com" nocase
        $domain69 = "aibotscale.com" nocase
        $domain70 = "aibrainatelier.com" nocase
        $domain71 = "aibrainframe.com" nocase
        $domain72 = "aibrainlogicc.com" nocase
        $domain73 = "aibrainmatrixed.com" nocase
        $domain74 = "aibrainyard.com" nocase
        $domain75 = "aibuildersguild.com" nocase
        $domain76 = "aibuildnet.com" nocase
        $domain77 = "aibuildspark.com" nocase
        $domain78 = "aibytepad.com" nocase
        $domain79 = "aicalcengine.com" nocase
        $domain80 = "aichatbeam.com" nocase
        $domain81 = "aichatfuse.com" nocase
        $domain82 = "aichattask.com" nocase
        $domain83 = "aichippad.com" nocase
        $domain84 = "aicloudcamp.com" nocase
        $domain85 = "aicloudlayer.com" nocase
        $domain86 = "aicloudreactor.com" nocase
        $domain87 = "aicloudthread.com" nocase
        $domain88 = "aicodealpha.com" nocase
        $domain89 = "aicodebeam.com" nocase
        $domain90 = "aicodebrain.com" nocase
        $domain91 = "aicodefoundry.com" nocase
        $domain92 = "aicodeport.com" nocase
        $domain93 = "aicognexora.com" nocase
        $domain94 = "aicognistack.com" nocase
        $domain95 = "aicognitiongrid.com" nocase
        $domain96 = "aicognitiveforge.com" nocase
        $domain97 = "aicognitiveframework.com" nocase
        $domain98 = "aicognivaults.com" nocase
        $domain99 = "aicomputedgrid.com" nocase

    condition:
        any of them
}

rule APT_UNC2529 {
    meta:
        description = "Indicators associated with APT UNC2529"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "doubleback, doubledrag, doubledrop"

    strings:
        $domain0 = "adupla.net" nocase
        $domain1 = "aibemarle.com" nocase
        $domain2 = "arcadiabay.org" nocase
        $domain3 = "austinheisey.com" nocase
        $domain4 = "bestcake.ca" nocase
        $domain5 = "bestwalletforbitcoin.com" nocase
        $domain6 = "bitcoinsacks.com" nocase
        $domain7 = "bonushelp.com" nocase
        $domain8 = "ceylonbungalows.net" nocase
        $domain9 = "chandol.com" nocase
        $domain10 = "clanvisits.com" nocase
        $domain11 = "closetdeal.com" nocase
        $domain12 = "daldhillon.com" nocase
        $domain13 = "desmoncreative.com" nocase
        $domain14 = "digitalagencyleeds.com" nocase
        $domain15 = "erbilmarriott.com" nocase
        $domain16 = "ethernetpedia.com" nocase
        $domain17 = "farmpork.com" nocase
        $domain18 = "fileamazon.com" nocase
        $domain19 = "gamesaccommodationscotland.com" nocase
        $domain20 = "gemralph.com" nocase
        $domain21 = "greathabibgroup.com" nocase
        $domain22 = "greeklife242.com" nocase
        $domain23 = "infomarketx.com" nocase
        $domain24 = "isjustlunch.com" nocase
        $domain25 = "jagunconsult.com" nocase
        $domain26 = "khodaycontrolsystem.com" nocase
        $domain27 = "klikbets.net" nocase
        $domain28 = "lasartoria.net" nocase
        $domain29 = "logicmyass.com" nocase
        $domain30 = "lottoangels.com" nocase
        $domain31 = "mangoldsengers.com" nocase
        $domain32 = "maninashop.com" nocase
        $domain33 = "oconeeveteransmemorial.com" nocase
        $domain34 = "onceprojects.com" nocase
        $domain35 = "p-leh.com" nocase
        $domain36 = "scottishhandcraft.com" nocase
        $domain37 = "seathisons.com" nocase
        $domain38 = "simcardhosting.com" nocase
        $domain39 = "skysatcam.com" nocase
        $domain40 = "smartnhappy.com" nocase
        $domain41 = "stayzarentals.com" nocase
        $domain42 = "stepearn.com" nocase
        $domain43 = "sugarmummylove.com" nocase
        $domain44 = "techooze.com" nocase
        $domain45 = "tigertigerbeads.com" nocase
        $domain46 = "totallyhealth-wealth.com" nocase
        $domain47 = "touristboardaccommodation.com" nocase
        $domain48 = "towncenterhotel.com" nocase
        $domain49 = "towncentrehotel.com" nocase
        $domain50 = "towncentrehotels.com" nocase
        $domain51 = "uaeworkpermit.com" nocase
        $domain52 = "vacuumcleanerpartsstore.com" nocase
        $domain53 = "zmrtu.com" nocase

    condition:
        any of them
}

rule APT_UNC2565 {
    meta:
        description = "Indicators associated with APT UNC2565"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "kakiosk.adsparkdev.com" nocase

    condition:
        any of them
}

rule APT_UNC2596 {
    meta:
        description = "Indicators associated with APT UNC2596"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "dustyhammock, meltingclaw, romcom"

    strings:
        $domain0 = "1drv.fileshare.direct" nocase
        $domain1 = "1drv.us.com" nocase
        $domain2 = "4qzm.com" nocase
        $domain3 = "adbefnts.dev" nocase
        $domain4 = "adcreative.pictures" nocase
        $domain5 = "adobe.cloudcreative.digital" nocase
        $domain6 = "advanced-ip-scaner.com" nocase
        $domain7 = "advanced-ip-scanners.com" nocase
        $domain8 = "altimata.org" nocase
        $domain9 = "apisolving.com" nocase
        $domain10 = "aspx.io" nocase
        $domain11 = "bentaxworld.com" nocase
        $domain12 = "budgetnews.org" nocase
        $domain13 = "campanole.com" nocase
        $domain14 = "certifysop.com" nocase
        $domain15 = "cethernet.com" nocase
        $domain16 = "cloudcreative.digital" nocase
        $domain17 = "combinedresidency.org" nocase
        $domain18 = "copdaemi.top" nocase
        $domain19 = "correctiv.sbs" nocase
        $domain20 = "creativeadb.com" nocase
        $domain21 = "cwise.store" nocase
        $domain22 = "dashboard.penofach.com" nocase
        $domain23 = "devhubs.dev" nocase
        $domain24 = "devolredir.com" nocase
        $domain25 = "digitalsolutionstime.com" nocase
        $domain26 = "dns-msn.com" nocase
        $domain27 = "dnsresolver.online" nocase
        $domain28 = "docstorage.link" nocase
        $domain29 = "drv2ms.com" nocase
        $domain30 = "drvmcprotect.com" nocase
        $domain31 = "economistjournal.cloud" nocase
        $domain32 = "fastshare.click" nocase
        $domain33 = "fileshare.direct" nocase
        $domain34 = "finformservice.com" nocase
        $domain35 = "gohazeldale.com" nocase
        $domain36 = "gov.mil.ua.aspx.io" nocase
        $domain37 = "ilogicflow.com" nocase
        $domain38 = "journalctd.live" nocase
        $domain39 = "kayakahead.net" nocase
        $domain40 = "keepas.org" nocase
        $domain41 = "linedrv.com" nocase
        $domain42 = "mcprotect.cloud" nocase
        $domain43 = "mctelemetryzone.com" nocase
        $domain44 = "melamorri.com" nocase
        $domain45 = "mil.ua.aspx.io" nocase
        $domain46 = "mill.co.ua" nocase
        $domain47 = "netstaticsinformation.com" nocase
        $domain48 = "notfiled.com" nocase
        $domain49 = "olminx.com" nocase
        $domain50 = "optasko.com" nocase
        $domain51 = "pap-cut.com" nocase
        $domain52 = "penofach.com" nocase
        $domain53 = "pos-st.top" nocase
        $domain54 = "postnordpakker.com" nocase
        $domain55 = "publicshare.link" nocase
        $domain56 = "rdp-devolutions.com" nocase
        $domain57 = "redditanalytics.pm" nocase
        $domain58 = "redirconnectwise.cloud" nocase
        $domain59 = "redircorrectiv.com" nocase
        $domain60 = "redjournal.cloud" nocase
        $domain61 = "sitepanel.top" nocase
        $domain62 = "speedymarker.com" nocase
        $domain63 = "srlaptop.com" nocase
        $domain64 = "startleague.net" nocase
        $domain65 = "store-images.org" nocase
        $domain66 = "ua.aspx.io" nocase
        $domain67 = "ukrainianworldcongress.info" nocase
        $domain68 = "webtimeapi.com" nocase
        $domain69 = "wexonlake.com" nocase
        $domain70 = "wirelessvezion.com" nocase
        $domain71 = "wirelesszone.top" nocase
        $domain72 = "wplsummit.com" nocase
        $domain73 = "wveeam.com" nocase
        $domain74 = "xeontime.com" nocase
        $domain75 = "you-supported.com" nocase
        $ip76 = "104.234.10.207"
        $ip77 = "104.234.239.26"
        $ip78 = "104.234.239.26"
        $ip79 = "104.234.239.26"
        $ip80 = "109.105.198.145"
        $ip81 = "15.235.203.250"
        $ip82 = "185.56.137.104"
        $ip83 = "2.57.90.16"
        $ip84 = "201.174.21.202"
        $ip85 = "201.174.21.202"
        $ip86 = "201.174.21.202"
        $ip87 = "217.195.153.39"
        $ip88 = "46.246.98.15"
        $ip89 = "65.21.27.250"
        $ip90 = "69.49.231.103"
        $ip91 = "69.49.245.55"

    condition:
        any of them
}

rule APT_UNC2814 {
    meta:
        description = "Indicators associated with APT UNC2814"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "gridtide"

    strings:
        $domain0 = "1cv2f3d5s6a9w.ddnsfree.com" nocase
        $domain1 = "admina.freeddns.org" nocase
        $domain2 = "afsaces.accesscam.org" nocase
        $domain3 = "ancisesic.accesscam.org" nocase
        $domain4 = "apiotc.duckdns.org" nocase
        $domain5 = "applebox.camdvr.org" nocase
        $domain6 = "appler.kozow.com" nocase
        $domain7 = "asdad21ww.freeddns.org" nocase
        $domain8 = "aw2o25forsbc.camdvr.org" nocase
        $domain9 = "awcc001jdaigfwdagdcew.giize.com" nocase
        $domain10 = "bab2o25com.accesscam.org" nocase
        $domain11 = "babaji.accesscam.org" nocase
        $domain12 = "babi5599ss.ddnsgeek.com" nocase
        $domain13 = "balabalabo.mywire.org" nocase
        $domain14 = "bggs.giize.com" nocase
        $domain15 = "bibabo.freeddns.org" nocase
        $domain16 = "binmol.webredirect.org" nocase
        $domain17 = "bioth.giize.com" nocase
        $domain18 = "bitel.mywire.org" nocase
        $domain19 = "boemobww.ddnsfree.com" nocase
        $domain20 = "brcallletme.theworkpc.com" nocase
        $domain21 = "btbtutil.theworkpc.com" nocase
        $domain22 = "btltan.ooguy.com" nocase
        $domain23 = "camcampkes.ddnsfree.com" nocase
        $domain24 = "camsqewivo.kozow.com" nocase
        $domain25 = "ccammutom.ddnsgeek.com" nocase
        $domain26 = "ccel.kozow.com" nocase
        $domain27 = "cdnvmtools.theworkpc.com" nocase
        $domain28 = "cloacpae.ddnsfree.com" nocase
        $domain29 = "cmwwoods1.theworkpc.com" nocase
        $domain30 = "cnrpaslceas.freeddns.org" nocase
        $domain31 = "codemicros12.gleeze.com" nocase
        $domain32 = "cp02odjaic.kozow.com" nocase
        $domain33 = "cressmiss.ooguy.com" nocase
        $domain34 = "cvabiasbae.ddnsfree.com" nocase
        $domain35 = "cvnoc01da1cjmnftsd.accesscam.org" nocase
        $domain36 = "cvpc01aenusocirem.accesscam.org" nocase
        $domain37 = "cvpc01cgsdfn53hgd.giize.com" nocase
        $domain38 = "dclcwpdtsdcc.ddnsfree.com" nocase
        $domain39 = "dlpossie.ddnsfree.com" nocase
        $domain40 = "dnsfreedb.ddnsfree.com" nocase
        $domain41 = "doboudix1024.mywire.org" nocase
        $domain42 = "docla1rocodetellkadihewfnt3.kozow.com" nocase
        $domain43 = "entel.kozow.com" nocase
        $domain44 = "evilginx2.loseyourip.com" nocase
        $domain45 = "examp1e.webredirect.org" nocase
        $domain46 = "faeelt.giize.com" nocase
        $domain47 = "fakjcsaeyhs.ddnsfree.com" nocase
        $domain48 = "fasceadvcva3.gleeze.com" nocase
        $domain49 = "ffosies2024.camdvr.org" nocase
        $domain50 = "fgdedd1dww.gleeze.com" nocase
        $domain51 = "filipinet.ddnsgeek.com" nocase
        $domain52 = "freeios.theworkpc.com" nocase
        $domain53 = "ftpuser14.gleeze.com" nocase
        $domain54 = "ftpzpak.kozow.com" nocase
        $domain55 = "gam00v4fric4omv.camdvr.org" nocase
        $domain56 = "globoss.kozow.com" nocase
        $domain57 = "gogo2025up.ddnsfree.com" nocase
        $domain58 = "googlel.gleeze.com" nocase
        $domain59 = "googles.accesscam.org" nocase
        $domain60 = "googles.ddnsfree.com" nocase
        $domain61 = "googlett.camdvr.org" nocase
        $domain62 = "googllabwws.gleeze.com" nocase
        $domain63 = "gtaldps31c.ddnsfree.com" nocase
        $domain64 = "hamkorg.kozow.com" nocase
        $domain65 = "honidoo.loseyourip.com" nocase
        $domain66 = "huygdr12.loseyourip.com" nocase
        $domain67 = "icekancusjhea.ddnsgeek.com" nocase
        $domain68 = "idstandsuui.kozow.com" nocase
        $domain69 = "indoodchat.theworkpc.com" nocase
        $domain70 = "jarvis001.freeddns.org" nocase
        $domain71 = "kaushalya.freeddns.org" nocase
        $domain72 = "khyes001ndfpnuewdm.kozow.com" nocase
        $domain73 = "kskxoscieontrolanel.gleeze.com" nocase
        $domain74 = "ksv01sokudwongsj.theworkpc.com" nocase
        $domain75 = "lcskiecjj.loseyourip.com" nocase
        $domain76 = "lcskiecs.ddnsfree.com" nocase
        $domain77 = "losiesca.ddnsgeek.com" nocase
        $domain78 = "lps2staging.ddnsfree.com" nocase
        $domain79 = "lsls.casacam.net" nocase
        $domain80 = "ltiuys.ddnsgeek.com" nocase
        $domain81 = "ltiuys.kozow.com" nocase
        $domain82 = "lxym.hlsx.xyz" nocase
        $domain83 = "mailsdy.gleeze.com" nocase
        $domain84 = "maliclick1.ddnsfree.com" nocase
        $domain85 = "mauritasszddb.ddnsfree.com" nocase
        $domain86 = "meetls.kozow.com" nocase
        $domain87 = "microsoft.bumbleshrimp.com" nocase
        $domain88 = "ml3.freeddns.org" nocase
        $domain89 = "mlksucnayesk.kozow.com" nocase
        $domain90 = "mlkzongking2024.kozow.com" nocase
        $domain91 = "mmmfaco2025.mywire.org" nocase
        $domain92 = "mms.bumbleshrimp.com" nocase
        $domain93 = "mmvmtools.giize.com" nocase
        $domain94 = "modgood.gleeze.com" nocase
        $domain95 = "mosplosaq.accesscam.org" nocase
        $domain96 = "mtnngservice.ddnsguru.com" nocase
        $domain97 = "mysql.casacam.net" nocase
        $domain98 = "myzrzy2026.ddnsfree.com" nocase
        $domain99 = "nenigncagvawr.giize.com" nocase

    condition:
        any of them
}

rule APT_UNC3500 {
    meta:
        description = "Indicators associated with APT UNC3500"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "vpn599147072.softether.net" nocase
        $ip1 = "34.92.40.189"
        $ip2 = "34.92.40.189"
        $ip3 = "45.76.98.184"
        $ip4 = "45.76.98.184"
        $ip5 = "45.76.98.184"

    condition:
        any of them
}

rule APT_UNC3535 {
    meta:
        description = "Indicators associated with APT UNC3535"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "187.109.15.2"

    condition:
        any of them
}

rule APT_UNC3886 {
    meta:
        description = "Indicators associated with APT UNC3886"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "tinyshell, redpenguin, riflespine"

    strings:
        $ip0 = "101.100.182.122"
        $ip1 = "116.88.34.184"
        $ip2 = "118.189.188.122"
        $ip3 = "118.193.63.40"
        $ip4 = "129.126.109.50"
        $ip5 = "158.140.135.244"
        $ip6 = "223.25.78.136"
        $ip7 = "45.77.39.28"
        $ip8 = "47.246.68.13"
        $ip9 = "8.222.225.8"

    condition:
        any of them
}

rule APT_UNC3890 {
    meta:
        description = "Indicators associated with APT UNC3890"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "account.office365update.live" nocase
        $domain1 = "account.sdfsfsdf.office365update.live" nocase
        $domain2 = "ads.celebritylife.news" nocase
        $domain3 = "aspiremovecentraldays.net" nocase
        $domain4 = "celebritylife.news" nocase
        $domain5 = "com.office365update.live" nocase
        $domain6 = "fileupload.shop" nocase
        $domain7 = "i.login.office365update.live" nocase
        $domain8 = "login.office365update.live" nocase
        $domain9 = "login.rnfacebook.com" nocase
        $domain10 = "login.sdfsfsdf.office365update.live" nocase
        $domain11 = "logincdn.sdfsfsdf.office365update.live" nocase
        $domain12 = "m.login.office365update.live" nocase
        $domain13 = "m.login.rnfacebook.com" nocase
        $domain14 = "m.site.rnfacebook.com" nocase
        $domain15 = "microsoft.office365update.live" nocase
        $domain16 = "microsoftonline.office365update.live" nocase
        $domain17 = "naturaldolls.store" nocase
        $domain18 = "ns1.office365update.live" nocase
        $domain19 = "ns2.office365update.live" nocase
        $domain20 = "office365update.live" nocase
        $domain21 = "outlook.office365update.live" nocase
        $domain22 = "outlook.sdfsfsdf.office365update.live" nocase
        $domain23 = "pfizerpoll.com" nocase
        $domain24 = "rnfacebook.com" nocase
        $domain25 = "sdfsfsdf.office365update.live" nocase
        $domain26 = "site.rnfacebook.com" nocase
        $domain27 = "static.login.rnfacebook.com" nocase
        $domain28 = "static.site.rnfacebook.com" nocase
        $domain29 = "test.office365update.live" nocase
        $domain30 = "xn--lirkedin-vkb.com" nocase
        $domain31 = "xxx-doll.com" nocase
        $ip32 = "161.35.123.176"

    condition:
        any of them
}

rule APT_UNC3966 {
    meta:
        description = "Indicators associated with APT UNC3966"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "ms-prod19-live.com" nocase

    condition:
        any of them
}

rule APT_UNC4108 {
    meta:
        description = "Indicators associated with APT UNC4108"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "ghostweaver"

    strings:
        $domain0 = "akami-cdns.com" nocase
        $domain1 = "cdns-clfr-dns.com" nocase
        $domain2 = "content-cdnsclfr.com" nocase
        $domain3 = "query-dns-cdn.com" nocase
        $domain4 = "query-js-ajax.com" nocase

    condition:
        any of them
}

rule APT_UNC4166 {
    meta:
        description = "Indicators associated with APT UNC4166"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "SPAREPART, STOWAWAY"

    strings:
        $domain0 = "56nk4qmwxcdd72yiaro7bxixvgf5awgmmzpodub7phmfsqylezu2tsid.onion.moe" nocase
        $domain1 = "cdnworld.org" nocase
        $domain2 = "ufowdauczwpa4enmzj2yyf7m4cbsjcaxxoyeebc2wdgzwnhvwhjf7iid.onion.moe" nocase
        $domain3 = "ufowdauczwpa4enmzj2yyf7m4cbsjcaxxoyeebc2wdgzwnhvwhjf7iid.onion.ws" nocase
        $ip4 = "193.142.30.166"
        $ip5 = "91.205.230.66"

    condition:
        any of them
}

rule APT_UNC4191 {
    meta:
        description = "Indicators associated with APT UNC4191"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "bluehaze, darkdew, mistcloak"

    strings:
        $domain0 = "closed.theworkpc.com" nocase

    condition:
        any of them
}

rule APT_UNC4210 {
    meta:
        description = "Indicators associated with APT UNC4210"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "kopiluwak, quietcanary"

    strings:
        $domain0 = "manager.surro.am" nocase
        $domain1 = "surro.am" nocase
        $ip2 = "194.67.209.186"

    condition:
        any of them
}

rule APT_UNC4221 {
    meta:
        description = "Indicators associated with APT UNC4221"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "212nj0b42w.web.telegram-account.host" nocase
        $domain1 = "658pvbhj2k7veemmv4.web.telegram-account.host" nocase
        $domain2 = "accept-action.site" nocase
        $domain3 = "account-guard.site" nocase
        $domain4 = "account-saver.com" nocase
        $domain5 = "account-viewer.com" nocase
        $domain6 = "add-group.site" nocase
        $domain7 = "cancel-action.site" nocase
        $domain8 = "cancel-auth.site" nocase
        $domain9 = "check-active.site" nocase
        $domain10 = "check.sign-cert.com" nocase
        $domain11 = "cloud.account-viewer.com" nocase
        $domain12 = "cloud.god-le.net" nocase
        $domain13 = "clouddrive.world" nocase
        $domain14 = "confirm-signal.site" nocase
        $domain15 = "confirm.account-viewer.com" nocase
        $domain16 = "confirmphone.site" nocase
        $domain17 = "defender-bot.site" nocase
        $domain18 = "delta.milgov.site" nocase
        $domain19 = "derzhposluhy.com" nocase
        $domain20 = "device.redirecl.com" nocase
        $domain21 = "dhl.redirecl.com" nocase
        $domain22 = "drive-share.site" nocase
        $domain23 = "drive.redirecl.com" nocase
        $domain24 = "emtserviceca.info" nocase
        $domain25 = "get.god-le.com" nocase
        $domain26 = "get.in-touc.com" nocase
        $domain27 = "get.mail-gov.com" nocase
        $domain28 = "get.sign-cert.com" nocase
        $domain29 = "god-le.com" nocase
        $domain30 = "god-le.net" nocase
        $domain31 = "google.drive-share.site" nocase
        $domain32 = "google.share-drive.site" nocase
        $domain33 = "group-invitation.site" nocase
        $domain34 = "group-teneta.online" nocase
        $domain35 = "group.kropyva.site" nocase
        $domain36 = "group.teneta.site" nocase
        $domain37 = "helperanalytics.ru" nocase
        $domain38 = "homeskart.shop" nocase
        $domain39 = "homeway.xyz" nocase
        $domain40 = "i-ua.account-guard.site" nocase
        $domain41 = "in-touc.com" nocase
        $domain42 = "ivanti.account-viewer.com" nocase
        $domain43 = "join-group.online" nocase
        $domain44 = "kropyva.group" nocase
        $domain45 = "kropyva.site" nocase
        $domain46 = "live.outloolc.com" nocase
        $domain47 = "mail-gov.com" nocase
        $domain48 = "mail-gov.net" nocase
        $domain49 = "mail.outloolc.com" nocase
        $domain50 = "mails.support" nocase
        $domain51 = "milgov.host" nocase
        $domain52 = "milgov.site" nocase
        $domain53 = "mirotrent.com" nocase
        $domain54 = "my.mail-gov.net" nocase
        $domain55 = "odwebp.com" nocase
        $domain56 = "outloolc.com" nocase
        $domain57 = "palantir.ink" nocase
        $domain58 = "passport-ukr-net.site" nocase
        $domain59 = "plntr.account-viewer.com" nocase
        $domain60 = "plntr.mirotrent.com" nocase
        $domain61 = "protect-password.site" nocase
        $domain62 = "qsrgh.site" nocase
        $domain63 = "qweasdzx.site" nocase
        $domain64 = "redirecl.com" nocase
        $domain65 = "share-drive.site" nocase
        $domain66 = "sign-cert.com" nocase
        $domain67 = "signal-confirm.site" nocase
        $domain68 = "signal-protect.host" nocase
        $domain69 = "spam.web-telegram.host" nocase
        $domain70 = "stellar.account-viewer.com" nocase
        $domain71 = "svc.odwebp.com" nocase
        $domain72 = "teiegram.host" nocase
        $domain73 = "telegram-account.host" nocase
        $domain74 = "telegram-auth.website" nocase
        $domain75 = "telegram-confirm.site" nocase
        $domain76 = "telegram.check-active.site" nocase
        $domain77 = "telegram.defender-bot.site" nocase
        $domain78 = "telegram.qweasdzx.site" nocase
        $domain79 = "telegram.token-defender.cloud" nocase
        $domain80 = "telegramm-account.site" nocase
        $domain81 = "teneta.add-group.site" nocase
        $domain82 = "teneta.group" nocase
        $domain83 = "teneta.join-group.online" nocase
        $domain84 = "teneta.site" nocase
        $domain85 = "token-defender.cloud" nocase
        $domain86 = "uspp.derzhposluhy.com" nocase
        $domain87 = "web-telegram.host" nocase
        $domain88 = "web.teiegram.host" nocase
        $domain89 = "web.telegram-account.host" nocase
        $domain90 = "web.telegramm-account.site" nocase
        $domain91 = "web.web.telegram-account.host" nocase
        $domain92 = "whatsapp-confirm.site" nocase
        $domain93 = "whatsapp.group-invitation.site" nocase
        $domain94 = "whatsapp.protect-password.site" nocase
        $ip95 = "185.225.35.75"

    condition:
        any of them
}

rule APT_UNC4553 {
    meta:
        description = "Indicators associated with APT UNC4553"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "ridile"

    strings:
        $domain0 = "2022-blanks.site" nocase
        $domain1 = "ashgrrwt.click" nocase
        $domain2 = "extenision-app.com" nocase
        $domain3 = "finandy.info" nocase
        $domain4 = "finandy.online" nocase
        $domain5 = "flnand.online" nocase
        $domain6 = "kz-smartbank.com" nocase
        $domain7 = "mareux.online" nocase
        $domain8 = "mmarx.quest" nocase
        $domain9 = "okxsat.xyz" nocase
        $domain10 = "pr-tracker.online" nocase
        $domain11 = "qivvi-3.click" nocase
        $domain12 = "serienjunkies.us" nocase
        $domain13 = "telegromcn.org" nocase
        $domain14 = "vceilinichego.ru" nocase
        $domain15 = "vse-blanki.online" nocase
        $ip16 = "146.70.79.75"

    condition:
        any of them
}

rule APT_UNC4841 {
    meta:
        description = "Indicators associated with APT UNC4841"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "SALTWATER, SEASPY, SEASIDE"

    strings:
        $domain0 = "aar.gandhibludtric.com" nocase
        $domain1 = "aria-hidden.com" nocase
        $domain2 = "asparticrooftop.com" nocase
        $domain3 = "availabilitydesired.us" nocase
        $domain4 = "bestfindthetruth.com" nocase
        $domain5 = "caret-right.com" nocase
        $domain6 = "chatscreend.com" nocase
        $domain7 = "chekoodver.com" nocase
        $domain8 = "cloudprocenter.com" nocase
        $domain9 = "clubworkmistake.com" nocase
        $domain10 = "col-lg.com" nocase
        $domain11 = "colourtinctem.com" nocase
        $domain12 = "componfrom.com" nocase
        $domain13 = "e-forwardviewupdata.com" nocase
        $domain14 = "fessionalwork.com" nocase
        $domain15 = "fitbookcatwer.com" nocase
        $domain16 = "fjtest-block.com" nocase
        $domain17 = "followkoon.com" nocase
        $domain18 = "gandhibludtric.com" nocase
        $domain19 = "gesturefavour.com" nocase
        $domain20 = "getdbecausehub.com" nocase
        $domain21 = "goldenunder.com" nocase
        $domain22 = "hateupopred.com" nocase
        $domain23 = "incisivelyfut.com" nocase
        $domain24 = "junsamyoung.com" nocase
        $domain25 = "lookpumrron.com" nocase
        $domain26 = "morrowadded.com" nocase
        $domain27 = "mx01.bestfindthetruth.com" nocase
        $domain28 = "newhkdaily.com" nocase
        $domain29 = "onlineeylity.com" nocase
        $domain30 = "qatarpenble.com" nocase
        $domain31 = "redbludfootvr.com" nocase
        $domain32 = "requiredvalue.com" nocase
        $domain33 = "ressicepro.com" nocase
        $domain34 = "shalaordereport.com" nocase
        $domain35 = "siderheycook.com" nocase
        $domain36 = "sinceretehope.com" nocase
        $domain37 = "singamofing.com" nocase
        $domain38 = "singnode.com" nocase
        $domain39 = "solveblemten.com" nocase
        $domain40 = "togetheroffway.com" nocase
        $domain41 = "toodblackrun.com" nocase
        $domain42 = "troublendsef.com" nocase
        $domain43 = "unfeelmoonvd.com" nocase
        $domain44 = "verfiedoccurr.com" nocase
        $domain45 = "waystrkeprosh.com" nocase
        $domain46 = "xdmgwctese.com" nocase
        $domain47 = "xxl17z.dnslog.cn" nocase
        $ip48 = "101.229.146.218"
        $ip49 = "101.229.146.218"
        $ip50 = "103.146.179.101"
        $ip51 = "103.146.179.101"
        $ip52 = "103.27.108.62"
        $ip53 = "103.27.108.62"
        $ip54 = "103.77.192.13"
        $ip55 = "103.77.192.13"
        $ip56 = "103.77.192.88"
        $ip57 = "103.77.192.88"
        $ip58 = "103.93.78.142"
        $ip59 = "103.93.78.142"
        $ip60 = "104.156.229.226"
        $ip61 = "104.156.229.226"
        $ip62 = "104.223.20.222"
        $ip63 = "104.223.20.222"
        $ip64 = "107.148.149.156"
        $ip65 = "107.148.219.227"
        $ip66 = "107.148.219.227"
        $ip67 = "107.148.219.53"
        $ip68 = "107.148.219.54"
        $ip69 = "107.148.219.54"
        $ip70 = "107.148.219.55"
        $ip71 = "107.148.219.55"
        $ip72 = "107.148.223.196"
        $ip73 = "107.148.223.196"
        $ip74 = "107.173.62.158"
        $ip75 = "107.173.62.158"
        $ip76 = "137.175.19.25"
        $ip77 = "137.175.19.25"
        $ip78 = "137.175.28.251"
        $ip79 = "137.175.28.251"
        $ip80 = "137.175.30.36"
        $ip81 = "137.175.30.36"
        $ip82 = "137.175.30.86"
        $ip83 = "137.175.30.86"
        $ip84 = "137.175.51.147"
        $ip85 = "137.175.53.170"
        $ip86 = "137.175.53.170"
        $ip87 = "137.175.53.17"
        $ip88 = "137.175.53.17"
        $ip89 = "137.175.53.218"
        $ip90 = "137.175.53.218"
        $ip91 = "137.175.60.252"
        $ip92 = "137.175.60.252"
        $ip93 = "137.175.60.253"
        $ip94 = "137.175.60.253"
        $ip95 = "137.175.78.66"
        $ip96 = "137.175.78.66"
        $ip97 = "139.84.227.9"

    condition:
        any of them
}

rule APT_UNC4899 {
    meta:
        description = "Indicators associated with APT UNC4899"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "JumpCloud"

    strings:
        $domain0 = "606qipai.com" nocase
        $domain1 = "alwaysckain.com" nocase
        $domain2 = "alwaysswarm.com" nocase
        $domain3 = "asplinc.com" nocase
        $domain4 = "basketsalute.com" nocase
        $domain5 = "bsef.or.kr" nocase
        $domain6 = "canolagroove.com" nocase
        $domain7 = "centos-packages.com" nocase
        $domain8 = "centos-pkg.org" nocase
        $domain9 = "centos-repos.org" nocase
        $domain10 = "contortonset.com" nocase
        $domain11 = "dallynk.com" nocase
        $domain12 = "datadog-cloud.com" nocase
        $domain13 = "datadog-graph.com" nocase
        $domain14 = "launchruse.com" nocase
        $domain15 = "nomadpkg.com" nocase
        $domain16 = "nomadpkgs.com" nocase
        $domain17 = "primerosauxiliosperu.com" nocase
        $domain18 = "prontoposer.com" nocase
        $domain19 = "redhat-packages.com" nocase
        $domain20 = "reggedrobin.com" nocase
        $domain21 = "relysudden.com" nocase
        $domain22 = "rentedpushy.com" nocase
        $domain23 = "sizzlesierra.com" nocase
        $domain24 = "sweptshut.com" nocase
        $domain25 = "toyourownbeat.com" nocase
        $domain26 = "yolenny.com" nocase
        $domain27 = "zscaler-api.org" nocase

    condition:
        any of them
}

rule APT_UNC4990 {
    meta:
        description = "Indicators associated with APT UNC4990"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "apiworld.cf" nocase
        $domain1 = "bobsmith.apiworld.cf" nocase
        $domain2 = "captcha.grouphelp.top" nocase
        $domain3 = "captcha.tgbot.it" nocase
        $domain4 = "davebeerblog.eu.org" nocase
        $domain5 = "eu1.microtunnel.it" nocase
        $domain6 = "euserv3.herokuapp.com" nocase
        $domain7 = "evinfeoptasw.dedyn.io" nocase
        $domain8 = "geraldonsboutique.altervista.org" nocase
        $domain9 = "lucaespo.altervista.org" nocase
        $domain10 = "lucaesposito.herokuapp.com" nocase
        $domain11 = "microtunnel.it" nocase
        $domain12 = "monumental.ga" nocase
        $domain13 = "ncnskjhrbefwifjhww.tk" nocase
        $domain14 = "studiofotografico35mm.altervista.org" nocase
        $domain15 = "wjecpujpanmwm.tk" nocase

    condition:
        any of them
}

rule APT_UNC5174 {
    meta:
        description = "Indicators associated with APT UNC5174"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "snowlight, vshell"

    strings:
        $domain0 = "9oogle.net" nocase
        $domain1 = "apib.googlespays.com" nocase
        $domain2 = "bootstrapcdn.fun" nocase
        $domain3 = "btt.evil.gooogleasia.com" nocase
        $domain4 = "c1oudf1are.com" nocase
        $domain5 = "chmobank.com" nocase
        $domain6 = "goo9le.net" nocase
        $domain7 = "googlespays.com" nocase
        $domain8 = "goole-app.com" nocase
        $domain9 = "https.sex666vr.com" nocase
        $domain10 = "huionepay.me" nocase
        $domain11 = "jajal.goo9le.net" nocase
        $domain12 = "javaw.virustotal.xyz" nocase
        $domain13 = "ks.evil.gooogleasia.com" nocase
        $domain14 = "l1.mo1vip.org" nocase
        $domain15 = "l1.topayapp.org" nocase
        $domain16 = "lin.c1oudf1are.com" nocase
        $domain17 = "lin.huionepay.me" nocase
        $domain18 = "lin.telegrams.icu" nocase
        $domain19 = "mcafeecdn.xyz" nocase
        $domain20 = "mo1vip.org" nocase
        $domain21 = "mtls.sex666vr.com" nocase
        $domain22 = "samsungcdn.com" nocase
        $domain23 = "start.bootstrapcdn.fun" nocase
        $domain24 = "telegrams.icu" nocase
        $domain25 = "topayapp.org" nocase
        $domain26 = "virustotal.xyz" nocase
        $domain27 = "vs.gooogleasia.com" nocase
        $domain28 = "w1.topayapp.org" nocase
        $domain29 = "wg.gooogleasia.com" nocase
        $domain30 = "ws.9oogle.net" nocase
        $domain31 = "ws.goo9le.net" nocase
        $domain32 = "ws.goole-app.com" nocase
        $domain33 = "ws.mo1vip.org" nocase
        $domain34 = "ws.z2s.us" nocase
        $domain35 = "z2s.us" nocase
        $ip36 = "124.221.120.25"
        $ip37 = "5.199.166.4"
        $ip38 = "5.199.166.4"
        $ip39 = "5.199.166.4"
        $ip40 = "84.32.22.130"
        $ip41 = "84.32.22.130"

    condition:
        any of them
}

rule APT_UNC5221 {
    meta:
        description = "Indicators associated with APT UNC5221"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "uta0178, verdantbamboo, warppanda"

    strings:
        $domain0 = "172-235-56-113.plesk.page" nocase
        $domain1 = "abbeglasses.s3.amazonaws.com" nocase
        $domain2 = "abode-dashboard-media.s3.ap-south-1.amazonaws.com" nocase
        $domain3 = "api.d-n-s.name" nocase
        $domain4 = "archivevalley-media.s3.amazonaws.com" nocase
        $domain5 = "azdatastore.workers.dev" nocase
        $domain6 = "barannclinic.com" nocase
        $domain7 = "bititer.org" nocase
        $domain8 = "blooming.s3.amazonaws.com" nocase
        $domain9 = "calixcloudinfo.com" nocase
        $domain10 = "catcher.requestcatcher.com" nocase
        $domain11 = "clickcom.click" nocase
        $domain12 = "clicko.click" nocase
        $domain13 = "devs.calixcloudinfo.com" nocase
        $domain14 = "duorhytm.fun" nocase
        $domain15 = "faoith.com" nocase
        $domain16 = "fconnect.s3.amazonaws.com" nocase
        $domain17 = "fiveworkscorp.com" nocase
        $domain18 = "gpoaccess.com" nocase
        $domain19 = "kitfloor.org" nocase
        $domain20 = "line-api.com" nocase
        $domain21 = "msazure.azdatastore.workers.dev" nocase
        $domain22 = "natsupport.net" nocase
        $domain23 = "openrbf.s3.amazonaws.com" nocase
        $domain24 = "performanceviewtools.com" nocase
        $domain25 = "psecure.pro" nocase
        $domain26 = "safe.rocks" nocase
        $domain27 = "secure-cama.com" nocase
        $domain28 = "service.systemsvcs.com" nocase
        $domain29 = "shapefiles.fews.net.s3.amazonaws.com" nocase
        $domain30 = "symantke.com" nocase
        $domain31 = "systemsvcs.com" nocase
        $domain32 = "telemetry.psecure.pro" nocase
        $domain33 = "the-mentor.s3.amazonaws.com" nocase
        $domain34 = "tkshopqd.s3.amazonaws.com" nocase
        $domain35 = "tnegadge.s3.amazonaws.com" nocase
        $domain36 = "trkbucket.s3.amazonaws.com" nocase
        $domain37 = "webb-institute.com" nocase
        $domain38 = "winfoacacorp.com" nocase
        $ip39 = "146.0.228.66"
        $ip40 = "146.0.228.66"
        $ip41 = "45.227.255.213"
        $ip42 = "66.42.68.120"
        $ip43 = "8.137.112.245"
        $ip44 = "81.2.216.78"

    condition:
        any of them
}

rule APT_UNC5537 {
    meta:
        description = "Indicators associated with APT UNC5537"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "146.70.117.210"
        $ip1 = "146.70.117.56"
        $ip2 = "146.70.119.24"
        $ip3 = "146.70.124.216"
        $ip4 = "146.70.165.227"
        $ip5 = "146.70.166.176"
        $ip6 = "146.70.171.112"
        $ip7 = "146.70.171.99"
        $ip8 = "154.47.30.137"
        $ip9 = "154.47.30.150"
        $ip10 = "162.33.177.32"
        $ip11 = "169.150.201.25"
        $ip12 = "173.44.63.112"
        $ip13 = "176.123.3.132"
        $ip14 = "176.123.6.193"
        $ip15 = "176.220.186.152"
        $ip16 = "184.147.100.29"
        $ip17 = "185.156.46.163"
        $ip18 = "185.213.155.241"
        $ip19 = "185.248.85.14"
        $ip20 = "185.248.85.59"
        $ip21 = "192.252.212.60"
        $ip22 = "193.32.126.233"
        $ip23 = "194.230.144.126"
        $ip24 = "194.230.144.50"
        $ip25 = "194.230.145.67"
        $ip26 = "194.230.145.76"
        $ip27 = "194.230.147.127"
        $ip28 = "194.230.148.99"
        $ip29 = "194.230.158.107"
        $ip30 = "194.230.158.178"
        $ip31 = "194.230.160.237"
        $ip32 = "194.230.160.5"
        $ip33 = "198.44.136.56"
        $ip34 = "198.44.136.82"
        $ip35 = "198.54.130.153"
        $ip36 = "198.54.131.152"
        $ip37 = "206.217.205.49"
        $ip38 = "37.19.210.21"
        $ip39 = "45.134.142.200"
        $ip40 = "45.27.26.205"
        $ip41 = "45.86.221.146"
        $ip42 = "5.47.87.202"
        $ip43 = "66.115.189.247"
        $ip44 = "79.127.217.44"
        $ip45 = "87.249.134.11"
        $ip46 = "93.115.0.49"
        $ip47 = "96.44.191.140"

    condition:
        any of them
}

rule APT_UNC5792 {
    meta:
        description = "Indicators associated with APT UNC5792"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "add-signal-group.com" nocase
        $domain1 = "add-signal-groups.com" nocase
        $domain2 = "group-signal.com" nocase
        $domain3 = "group-signal.tech" nocase
        $domain4 = "groups-signal.site" nocase
        $domain5 = "signal-device-off.online" nocase
        $domain6 = "signal-group-add.com" nocase
        $domain7 = "signal-group.site" nocase
        $domain8 = "signal-group.tech" nocase
        $domain9 = "signal-groups-add.com" nocase
        $domain10 = "signal-groups.site" nocase
        $domain11 = "signal-groups.tech" nocase
        $domain12 = "signal-security.online" nocase
        $domain13 = "signal-security.site" nocase
        $domain14 = "signalgroup.site" nocase
        $domain15 = "signals-group.com" nocase

    condition:
        any of them
}

rule APT_UNC5812 {
    meta:
        description = "Indicators associated with APT UNC5812"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "civildefense.com.ua" nocase
        $domain1 = "fu-laravel.onrender.com" nocase
        $domain2 = "h315225216.nichost.ru" nocase

    condition:
        any of them
}

rule APT_UNC5952 {
    meta:
        description = "Indicators associated with APT UNC5952"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "12support.top" nocase
        $domain1 = "6559464.com" nocase
        $domain2 = "accesspoint.cc" nocase
        $domain3 = "admin.flywidus.co" nocase
        $domain4 = "atgajroker.icu" nocase
        $domain5 = "atmolatori.cyou" nocase
        $domain6 = "atmolatori.icu" nocase
        $domain7 = "awedinetwork.com" nocase
        $domain8 = "beri1.com" nocase
        $domain9 = "clmhelp.top" nocase
        $domain10 = "cloud.vshell.io" nocase
        $domain11 = "cogajroker.icu" nocase
        $domain12 = "cqhelp.top" nocase
        $domain13 = "csupport.ch" nocase
        $domain14 = "dealr.help" nocase
        $domain15 = "do68iyckuy.emerge.co.zw" nocase
        $domain16 = "dshelp.top" nocase
        $domain17 = "edg-rt1.top" nocase
        $domain18 = "elioua5.top" nocase
        $domain19 = "exnpanel1.top" nocase
        $domain20 = "fposhelp.com" nocase
        $domain21 = "gajrokerist.icu" nocase
        $domain22 = "gajrokerring.icu" nocase
        $domain23 = "gajrokerware.icu" nocase
        $domain24 = "glueconnect.com" nocase
        $domain25 = "gomolatori.cyou" nocase
        $domain26 = "gomolatori.icu" nocase
        $domain27 = "gthelp.top" nocase
        $domain28 = "gxclp2.top" nocase
        $domain29 = "help26.ca" nocase
        $domain30 = "helpmysupport.top" nocase
        $domain31 = "icrm-tr3.top" nocase
        $domain32 = "itmanagers.io" nocase
        $domain33 = "jjghelp.top" nocase
        $domain34 = "jxhelp.top" nocase
        $domain35 = "kaptohelp.top" nocase
        $domain36 = "kryzuxyzhosting.com" nocase
        $domain37 = "lamolatori.cyou" nocase
        $domain38 = "lamolatori.icu" nocase
        $domain39 = "lowcarbsupport.nl" nocase
        $domain40 = "lwhelp.top" nocase
        $domain41 = "medion-001-site1.ctempurl.com" nocase
        $domain42 = "mgbhelp.top" nocase
        $domain43 = "mghelp.top" nocase
        $domain44 = "mkpanel.connectagent.online" nocase
        $domain45 = "mohamedsisyxyz.com" nocase
        $domain46 = "molatoriby.cyou" nocase
        $domain47 = "molatoriby.icu" nocase
        $domain48 = "molatorier.cyou" nocase
        $domain49 = "molatorier.icu" nocase
        $domain50 = "molatoriism.cyou" nocase
        $domain51 = "molatoriism.icu" nocase
        $domain52 = "molatoriist.cyou" nocase
        $domain53 = "molatoriist.icu" nocase
        $domain54 = "molatoriit.cyou" nocase
        $domain55 = "molatoriit.icu" nocase
        $domain56 = "molatorila.cyou" nocase
        $domain57 = "molatorila.icu" nocase
        $domain58 = "molatoriline.cyou" nocase
        $domain59 = "molatoriline.icu" nocase
        $domain60 = "molatorimax.cyou" nocase
        $domain61 = "molatorimax.icu" nocase
        $domain62 = "molatoriora.cyou" nocase
        $domain63 = "molatoriora.icu" nocase
        $domain64 = "molatoripro.cyou" nocase
        $domain65 = "molatoripro.icu" nocase
        $domain66 = "molatorister.cyou" nocase
        $domain67 = "molatorister.icu" nocase
        $domain68 = "molatorisy.cyou" nocase
        $domain69 = "molatorisy.icu" nocase
        $domain70 = "molatoriup.cyou" nocase
        $domain71 = "molatoriup.icu" nocase
        $domain72 = "moqadiski.com" nocase
        $domain73 = "mr26panel.top" nocase
        $domain74 = "nonopanel.top" nocase
        $domain75 = "nphelp.top" nocase
        $domain76 = "numolatori.cyou" nocase
        $domain77 = "numolatori.icu" nocase
        $domain78 = "nwpihelp.top" nocase
        $domain79 = "omvtr-ud.top" nocase
        $domain80 = "onmolatori.cyou" nocase
        $domain81 = "onmolatori.icu" nocase
        $domain82 = "orhelp.top" nocase
        $domain83 = "plphelp.top" nocase
        $domain84 = "pnbf-gv.top" nocase
        $domain85 = "promolatori.cyou" nocase
        $domain86 = "promolatori.icu" nocase
        $domain87 = "ptbhelp.top" nocase
        $domain88 = "pzhelp.top" nocase
        $domain89 = "qc3699.jadonparod.cyou" nocase
        $domain90 = "qc3699.kafinora.cyou" nocase
        $domain91 = "qdhy5-pr.top" nocase
        $domain92 = "regajroker.icu" nocase
        $domain93 = "remoteconnection.com" nocase
        $domain94 = "rgbxyzhosting.com" nocase
        $domain95 = "ricpnew1.top" nocase
        $domain96 = "rjpanelplus.top" nocase
        $domain97 = "rtkhelp.top" nocase
        $domain98 = "samolatori.cyou" nocase
        $domain99 = "samolatori.icu" nocase

    condition:
        any of them
}

rule APT_UNC6293 {
    meta:
        description = "Indicators associated with APT UNC6293"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "91.190.191.117"

    condition:
        any of them
}

rule APT_UNC6353 {
    meta:
        description = "Indicators associated with APT UNC6353"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "darksword"

    strings:
        $domain0 = "afewminago.site" nocase
        $domain1 = "cartned.sheexcell.ink" nocase
        $domain2 = "cdn.cdncounter.net" nocase
        $domain3 = "cdn.uacounter.com" nocase
        $domain4 = "cdncounter.net" nocase
        $domain5 = "count.cdncounter.net" nocase
        $domain6 = "downdown.online" nocase
        $domain7 = "duflaro.com" nocase
        $domain8 = "escofiringbijou.com" nocase
        $domain9 = "inventorepkrje.sheexcell.ink" nocase
        $domain10 = "iokert.com" nocase
        $domain11 = "lifechangerai.site" nocase
        $domain12 = "link.sheexcell.ink" nocase
        $domain13 = "mxloft.sheexcell.ink" nocase
        $domain14 = "nuceciwa138.xyz" nocase
        $domain15 = "rhdcnwjnwf.site" nocase
        $domain16 = "sheexcell.ink" nocase
        $domain17 = "shkaacloud.ink" nocase
        $domain18 = "siekeltd.com" nocase
        $domain19 = "sqwas.shapelie.com" nocase
        $domain20 = "static.cdncounter.net" nocase
        $domain21 = "t.sheexcell.ink" nocase
        $domain22 = "touch-n-go.online" nocase
        $domain23 = "uacounter.com" nocase
        $domain24 = "world-news.site" nocase
        $domain25 = "wwteam.space" nocase

    condition:
        any of them
}

rule APT_UNC6691 {
    meta:
        description = "Indicators associated with APT UNC6691"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "plasmagrid, coruna"

    strings:
        $domain0 = "00c397xmk7.shop" nocase
        $domain1 = "00da.6hv86gxz.com" nocase
        $domain2 = "0159.axmatx.com" nocase
        $domain3 = "017.xdjuvoau.xyz" nocase
        $domain4 = "01b26ddfd3.top" nocase
        $domain5 = "01k.cc" nocase
        $domain6 = "022.furzocpc.cc" nocase
        $domain7 = "0221f016.6hv86gxz.com" nocase
        $domain8 = "025f.cjmekxr.xyz" nocase
        $domain9 = "027.st" nocase
        $domain10 = "0278.fxexebji.org" nocase
        $domain11 = "028mfsb.com" nocase
        $domain12 = "035b1c.xlgxyf.net" nocase
        $domain13 = "03f6aef6fd.top" nocase
        $domain14 = "0462b0.xdkfog.net" nocase
        $domain15 = "047.auyciwmw.com" nocase
        $domain16 = "04f327f914.top" nocase
        $domain17 = "054.esqifis.com" nocase
        $domain18 = "063.heppmpuz.org" nocase
        $domain19 = "0661.vdrywdi.xyz" nocase
        $domain20 = "069.st" nocase
        $domain21 = "06bf0.crfbbarx.com" nocase
        $domain22 = "06ee.vcfwvb.com" nocase
        $domain23 = "070052.sod777.com" nocase
        $domain24 = "07c0.ybbshhn.com" nocase
        $domain25 = "07f61.ncjqeyid.com" nocase
        $domain26 = "0847.zcfniju.cc" nocase
        $domain27 = "09688.xkbaamgc.cc" nocase
        $domain28 = "0992.app" nocase
        $domain29 = "099339.6hv86gxz.com" nocase
        $domain30 = "099ae.qcechaw.cc" nocase
        $domain31 = "0am15.com" nocase
        $domain32 = "0b2b.dljuhnea.com" nocase
        $domain33 = "0b461.xdjuvoau.xyz" nocase
        $domain34 = "0b6c80a39c.top" nocase
        $domain35 = "0b87ed69.xlgxyf.net" nocase
        $domain36 = "0b88.mqztymvz.cc" nocase
        $domain37 = "0ba7.vqlbhbmo.xyz" nocase
        $domain38 = "0bb7.dmjdwvpy.com" nocase
        $domain39 = "0ce1.dljuhnea.com" nocase
        $domain40 = "0cncoxi.com" nocase
        $domain41 = "0d0.ozhignq.com" nocase
        $domain42 = "0dc48.xjhvsgg.xyz" nocase
        $domain43 = "0de.ofvtspr.xyz" nocase
        $domain44 = "0e2a2.xlgxyf.net" nocase
        $domain45 = "0e8.kqyxwyb.xyz" nocase
        $domain46 = "0fx7qmdggegytul.xyz" nocase
        $domain47 = "0gab6nun8ubl2pk.xyz" nocase
        $domain48 = "0jijrwbzxzzxz04.xyz" nocase
        $domain49 = "0opus.com" nocase
        $domain50 = "0r97p.com" nocase
        $domain51 = "1.votetexas.xyz" nocase
        $domain52 = "100000000115d9.sod777.com" nocase
        $domain53 = "100000000199e6.sod777.com" nocase
        $domain54 = "10000000024523.sod777.com" nocase
        $domain55 = "10000000026e1e.sod777.com" nocase
        $domain56 = "1000000002e39f.sod777.com" nocase
        $domain57 = "10000000037c14.sod777.com" nocase
        $domain58 = "1000000004ae15.sod777.com" nocase
        $domain59 = "1000000004b0cc.sod777.com" nocase
        $domain60 = "10000000051e09.sod777.com" nocase
        $domain61 = "1000000006107.sod777.com" nocase
        $domain62 = "10000000061892.sod777.com" nocase
        $domain63 = "10000000080bd7.sod777.com" nocase
        $domain64 = "10000000086ecf.sod777.com" nocase
        $domain65 = "1002906492a419.sod777.com" nocase
        $domain66 = "100dd.sod777.com" nocase
        $domain67 = "100de.xtikbxvv.top" nocase
        $domain68 = "101.vqlbhbmo.xyz" nocase
        $domain69 = "101477049.252fe.sod777.com" nocase
        $domain70 = "1017c.sod777.com" nocase
        $domain71 = "1026f.sod777.com" nocase
        $domain72 = "102a1.sod777.com" nocase
        $domain73 = "10323db.sod777.com" nocase
        $domain74 = "104298016.25fd.sod777.com" nocase
        $domain75 = "1052.sod777.com" nocase
        $domain76 = "10746618620e82.sod777.com" nocase
        $domain77 = "109da.sod777.com" nocase
        $domain78 = "10b4d.sod777.com" nocase
        $domain79 = "10e07.sod777.com" nocase
        $domain80 = "10e24.sod777.com" nocase
        $domain81 = "10faf712fc11.com" nocase
        $domain82 = "10ff3.xjhvsgg.xyz" nocase
        $domain83 = "110f.sod777.com" nocase
        $domain84 = "1124e.ryvjugi.com" nocase
        $domain85 = "112b.kjtwhgda.tips" nocase
        $domain86 = "113484032.3ea61.sod777.com" nocase
        $domain87 = "115228239.377125217b713.sod777.com" nocase
        $domain88 = "1163.sod777.com" nocase
        $domain89 = "117c1.sod777.com" nocase
        $domain90 = "11d28.sod777.com" nocase
        $domain91 = "120.st" nocase
        $domain92 = "120198456.43605.sod777.com" nocase
        $domain93 = "12056.sod777.com" nocase
        $domain94 = "1208190011dc9.sod777.com" nocase
        $domain95 = "1215577532ead6.sod777.com" nocase
        $domain96 = "1216.st" nocase
        $domain97 = "1216.tw" nocase
        $domain98 = "121756948c517.sod777.com" nocase
        $domain99 = "122562cf0.sod777.com" nocase
        $ip100 = "151.245.104.179"
        $ip101 = "43.103.5.166"
        $ip102 = "43.110.83.200"
        $ip103 = "43.135.167.226"
        $ip104 = "67.215.247.183"

    condition:
        any of them
}

rule APT_UNC6692 {
    meta:
        description = "Indicators associated with APT UNC6692"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "snowbelt, snowglaze"

    strings:
        $domain0 = "cloudfront-021.s3.us-west-2.amazonaws.com" nocase
        $domain1 = "sad4w7h913-b4a57f9c36eb.herokuapp.com" nocase
        $domain2 = "service-page-11369-28315-outlook.s3.us-west-2.amazonaws.com" nocase
        $domain3 = "service-page-18968-2419-outlook.s3.us-west-2.amazonaws.com" nocase
        $domain4 = "service-page-25144-30466-outlook.s3.us-west-2.amazonaws.com" nocase

    condition:
        any of them
}

rule APT_UNC961 {
    meta:
        description = "Indicators associated with APT UNC961"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $ip0 = "107.181.187.184"
        $ip1 = "107.181.187.184"
        $ip2 = "149.28.200.140"
        $ip3 = "149.28.71.70"
        $ip4 = "162.33.178.149"
        $ip5 = "185.172.129.215"
        $ip6 = "195.149.87.87"
        $ip7 = "34.102.54.152"
        $ip8 = "45.61.136.188"

    condition:
        any of them
}

rule APT_UNCLASSIFIED {
    meta:
        description = "Indicators associated with APT UNCLASSIFIED"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "008php.com" nocase
        $domain1 = "01mirror.com.ua" nocase
        $domain2 = "0660sf.com" nocase
        $domain3 = "071790.000webhostapp.com" nocase
        $domain4 = "1.handprintscariness.ru" nocase
        $domain5 = "18center.com" nocase
        $domain6 = "20.3323sf.com" nocase
        $domain7 = "2021olympic.cn" nocase
        $domain8 = "2021olympics.jp" nocase
        $domain9 = "2021olympicupdates.com" nocase
        $domain10 = "2021olympicupdates.live" nocase
        $domain11 = "2021olympicupdateslive.com" nocase
        $domain12 = "2073.mobi" nocase
        $domain13 = "24ua.website" nocase
        $domain14 = "25665.club" nocase
        $domain15 = "25665.me" nocase
        $domain16 = "300bt.com" nocase
        $domain17 = "33016.club" nocase
        $domain18 = "3323sf.com" nocase
        $domain19 = "3s.aliqwenapi.com" nocase
        $domain20 = "4sdfaash.mypi.co" nocase
        $domain21 = "4sdfaashe.mypi.co" nocase
        $domain22 = "60431.club" nocase
        $domain23 = "7077.000webhostapp.com" nocase
        $domain24 = "75735.club" nocase
        $domain25 = "77444.club" nocase
        $domain26 = "78276.ussdns01.heketwe.com" nocase
        $domain27 = "78276.ussdns02.heketwe.com" nocase
        $domain28 = "80001.me" nocase
        $domain29 = "816e-182-227-90-53.ngrok.io" nocase
        $domain30 = "82813.club" nocase
        $domain31 = "86wts86a8j.com" nocase
        $domain32 = "881.000webhostapp.com" nocase
        $domain33 = "8d.cloudops-api.com" nocase
        $domain34 = "EuDbSyncUp.com" nocase
        $domain35 = "Jdokdo.ml" nocase
        $domain36 = "Jospubs.com" nocase
        $domain37 = "MsCupDb.com" nocase
        $domain38 = "UsMobileSos.com" nocase
        $domain39 = "a.00-online.com" nocase
        $domain40 = "a7788.1apps.com" nocase
        $domain41 = "aaaaaaaahmad.no-ip.biz" nocase
        $domain42 = "abbaass313.hopto.org" nocase
        $domain43 = "abbarhs.mypi.co" nocase
        $domain44 = "abbarhsa.mypi.co" nocase
        $domain45 = "abc69696969.vicp.net" nocase
        $domain46 = "abdillahzraibi.no-ip.biz" nocase
        $domain47 = "abdou36.noip.me" nocase
        $domain48 = "abevahack123.no-ip.biz" nocase
        $domain49 = "acccountsgoog1e.com" nocase
        $domain50 = "account-mail.info" nocase
        $domain51 = "accountapp.xyz" nocase
        $domain52 = "accountsgoog1e.com" nocase
        $domain53 = "acrobatverify.com" nocase
        $domain54 = "ado-read-parser.com" nocase
        $domain55 = "adobeactiveupdate.com" nocase
        $domain56 = "adobeactiveupdates.com" nocase
        $domain57 = "adobeseupdater.com" nocase
        $domain58 = "ads.teleryanhart.com" nocase
        $domain59 = "adstelemetry.com" nocase
        $domain60 = "aetye.ml" nocase
        $domain61 = "affiser.xyz" nocase
        $domain62 = "aghkf.ml" nocase
        $domain63 = "agpt.ajb.shaanxigas.com" nocase
        $domain64 = "ahalteke-gov.ru" nocase
        $domain65 = "ahmad83t.no-ip.biz" nocase
        $domain66 = "alaa170.no-ip.org" nocase
        $domain67 = "aldimarche.eu" nocase
        $domain68 = "alexandr01299.xyz" nocase
        $domain69 = "alialzainabe.mooo.com" nocase
        $domain70 = "aliqwenapi.com" nocase
        $domain71 = "aljazeera.cc" nocase
        $domain72 = "alkator.dns53.biz" nocase
        $domain73 = "allal.x64.me" nocase
        $domain74 = "allsoulu.com" nocase
        $domain75 = "am.my-zo.org" nocase
        $domain76 = "amana1.duckdns.org" nocase
        $domain77 = "ammopak.site" nocase
        $domain78 = "an.droidsuper.su" nocase
        $domain79 = "android.no-ip.org" nocase
        $domain80 = "androidupdaters.com" nocase
        $domain81 = "anroideex1.noip.me" nocase
        $domain82 = "aoaviations.com" nocase
        $domain83 = "api.doubles.click" nocase
        $domain84 = "api.infinitycloud.info" nocase
        $domain85 = "apiupdate.com" nocase
        $domain86 = "appliedcontextid.com" nocase
        $domain87 = "arabindex.info" nocase
        $domain88 = "armaanapp.in" nocase
        $domain89 = "armenpress.org" nocase
        $domain90 = "armlur.org" nocase
        $domain91 = "armradio.org" nocase
        $domain92 = "armtimes.net" nocase
        $domain93 = "armtimes.org" nocase
        $domain94 = "arrowservice.net" nocase
        $domain95 = "asbares.com" nocase
        $domain96 = "asdf.avstore.com.tw" nocase
        $domain97 = "asdf.skypetm.com.tw" nocase
        $domain98 = "asmkpo.com" nocase
        $domain99 = "atessan.online" nocase
        $ip100 = "103.117.120.129"
        $ip101 = "103.117.120.181"
        $ip102 = "103.117.120.182"
        $ip103 = "103.233.11.162"
        $ip104 = "103.97.128.53"
        $ip105 = "104.248.153.204"
        $ip106 = "104.248.153.204"
        $ip107 = "104.255.66.139"
        $ip108 = "108.181.165.94"
        $ip109 = "109.237.97.43"
        $ip110 = "109.237.97.4"
        $ip111 = "111.20.145.84"
        $ip112 = "111.90.150.37"
        $ip113 = "122.10.82.65"
        $ip114 = "122.10.93.136"
        $ip115 = "13.211.167.218"
        $ip116 = "135.125.107.221"
        $ip117 = "137.184.67.33"
        $ip118 = "137.220.180.39"
        $ip119 = "138.124.228.103"
        $ip120 = "138.68.56.176"
        $ip121 = "138.68.56.176"
        $ip122 = "143.110.189.141"
        $ip123 = "146.70.161.78"
        $ip124 = "146.70.233.83"
        $ip125 = "147.78.46.40"
        $ip126 = "147.78.46.40"
        $ip127 = "150.241.97.10"
        $ip128 = "154.82.92.160"
        $ip129 = "158.160.5.218"
        $ip130 = "161.97.167.88"
        $ip131 = "165.232.186.197"
        $ip132 = "165.232.186.197"
        $ip133 = "167.179.66.121"
        $ip134 = "167.71.226.171"
        $ip135 = "167.71.226.171"
        $ip136 = "167.71.226.171"
        $ip137 = "167.71.226.171"
        $ip138 = "167.71.226.171"
        $ip139 = "167.71.226.171"
        $ip140 = "167.71.226.171"
        $ip141 = "167.86.98.190"
        $ip142 = "169.40.2.68"
        $ip143 = "172.105.34.34"
        $ip144 = "172.105.34.34"
        $ip145 = "172.105.34.34"
        $ip146 = "172.105.34.34"
        $ip147 = "173.212.220.230"
        $ip148 = "173.212.254.151"
        $ip149 = "173.249.38.99"

    condition:
        any of them
}

rule APT_USH {
    meta:
        description = "Indicators associated with APT USH"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "unfading sea haze"

    strings:
        $domain0 = "adswt.com" nocase
        $domain1 = "airst.giize.com" nocase
        $domain2 = "api.bitdefenderupdate.org" nocase
        $domain3 = "api.simpletra.com" nocase
        $domain4 = "auth.bitdefenderupdate.com" nocase
        $domain5 = "babystats.dnset.com" nocase
        $domain6 = "bit.kozow.com" nocase
        $domain7 = "bitdefenderupdate.com" nocase
        $domain8 = "bitdefenderupdate.org" nocase
        $domain9 = "bomloginset.com" nocase
        $domain10 = "cdn.g8z.net" nocase
        $domain11 = "consilium.dnset.com" nocase
        $domain12 = "dns-log.d-n-s.org.uk" nocase
        $domain13 = "dns.g8z.net" nocase
        $domain14 = "employee.mywire.org" nocase
        $domain15 = "fc.adswt.com" nocase
        $domain16 = "helpdesk.fxnxs.com" nocase
        $domain17 = "images.emldn.com" nocase
        $domain18 = "link.theworkguyoo.com" nocase
        $domain19 = "linklab.blinklab.com" nocase
        $domain20 = "loadviber.webredirect.org" nocase
        $domain21 = "mail.adswt.com" nocase
        $domain22 = "mail.bomloginset.com" nocase
        $domain23 = "mail.pcygphil.com" nocase
        $domain24 = "mail.simpletra.com" nocase
        $domain25 = "mail.theworkguyoo.com" nocase
        $domain26 = "manags.twilightparadox.com" nocase
        $domain27 = "message.ooguy.com" nocase
        $domain28 = "news.nevuer.com" nocase
        $domain29 = "newy.hifiliving.com" nocase
        $domain30 = "ns2.theworkguyoo.com" nocase
        $domain31 = "payroll.mywire.org" nocase
        $domain32 = "pcygphil.com" nocase
        $domain33 = "provider.giize.com" nocase
        $domain34 = "rest.redirectme.net" nocase
        $domain35 = "simpletra.com" nocase
        $domain36 = "sopho.kozow.com" nocase
        $domain37 = "spcg.lunaticfridge.com" nocase
        $domain38 = "theworkguyoo.com" nocase
        $domain39 = "upupdate.ooguy.com" nocase
        $domain40 = "word.emldn.com" nocase
        $ip41 = "139.180.216.33"
        $ip42 = "139.180.221.55"
        $ip43 = "139.59.61.42"
        $ip44 = "142.93.80.236"
        $ip45 = "143.198.80.75"
        $ip46 = "146.185.136.221"
        $ip47 = "152.89.161.26"
        $ip48 = "154.90.34.83"
        $ip49 = "165.22.104.184"
        $ip50 = "165.232.84.56"
        $ip51 = "167.99.222.58"
        $ip52 = "178.128.19.134"
        $ip53 = "185.195.237.114"
        $ip54 = "185.198.57.135"
        $ip55 = "185.244.129.60"
        $ip56 = "185.244.130.34"
        $ip57 = "194.5.250.54"
        $ip58 = "206.189.153.85"
        $ip59 = "45.32.125.175"
        $ip60 = "68.183.185.80"
        $ip61 = "91.235.143.251"
        $ip62 = "95.216.63.54"

    condition:
        any of them
}

rule APT_VAJRAELEPH {
    meta:
        description = "Indicators associated with APT VAJRAELEPH"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "APT-Q-43, VajraSpy"

    strings:
        $domain0 = "appplace.shop" nocase
        $domain1 = "appz.live" nocase
        $domain2 = "appzshare.club" nocase
        $domain3 = "appzshare.digital" nocase
        $domain4 = "apzshare.club" nocase

    condition:
        any of them
}

rule APT_VENOMSPIDER {
    meta:
        description = "Indicators associated with APT VENOMSPIDER"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "goldenchickens, moreeggs, revc2"

    strings:
        $domain0 = "anuffrost.com" nocase
        $domain1 = "api.cloudservers.kz" nocase
        $domain2 = "api.incapdns.kz" nocase
        $domain3 = "api.sharefiles.center" nocase
        $domain4 = "api.totalsphere.center" nocase
        $domain5 = "avadgray.org" nocase
        $domain6 = "beta.w3.org.kz" nocase
        $domain7 = "blog.jasonlees.com" nocase
        $domain8 = "boldvertex.store" nocase
        $domain9 = "cast.voxcdn.kz" nocase
        $domain10 = "contactlistsagregator.com" nocase
        $domain11 = "developer.master.org.kz" nocase
        $domain12 = "dns.hahdyman.com" nocase
        $domain13 = "drive.fileio.center" nocase
        $domain14 = "fileio.center" nocase
        $domain15 = "finatick.com" nocase
        $domain16 = "gdrive.rest" nocase
        $domain17 = "incapdns.kz" nocase
        $domain18 = "interrafcu.com" nocase
        $domain19 = "jonatechlab.com" nocase
        $domain20 = "mail.incapdns.kz" nocase
        $domain21 = "mail.rediffmail.kz" nocase
        $domain22 = "maps.doaglas.com" nocase
        $domain23 = "master.org.kz" nocase
        $domain24 = "monstrack.org" nocase
        $domain25 = "nopsec.org" nocase
        $domain26 = "onlinemail.kz" nocase
        $domain27 = "pub-ee3b9adcbb354679b5c35d5210673997.r2.dev" nocase
        $domain28 = "qb-hos.pages.dev" nocase
        $domain29 = "report.monicabellucci.kz" nocase
        $domain30 = "ryanberardi.com" nocase
        $domain31 = "secure.cloudserv.ink" nocase
        $domain32 = "seopager.xyz" nocase
        $domain33 = "sharefiles.center" nocase
        $domain34 = "stats.wp.org.kz" nocase
        $domain35 = "swiftvantage.online" nocase
        $domain36 = "swissblog.org" nocase
        $domain37 = "tonsandmillions.com" nocase
        $domain38 = "tool.municipiodechepo.org" nocase
        $domain39 = "totalsphere.center" nocase
        $domain40 = "usstaffing.services" nocase
        $domain41 = "vad.totalsphere.center" nocase
        $domain42 = "voxcdn.kz" nocase
        $domain43 = "w3.org.kz" nocase
        $domain44 = "waveax.net" nocase
        $domain45 = "wetransfers.io" nocase
        $domain46 = "winapi.net" nocase
        $domain47 = "wp.org.kz" nocase
        $domain48 = "yerra.org" nocase
        $ip49 = "170.75.168.151"
        $ip50 = "208.85.17.52"
        $ip51 = "217.69.8.13"
        $ip52 = "65.20.104.138"
        $ip53 = "65.20.104.138"
        $ip54 = "65.20.104.150"
        $ip55 = "65.20.104.212"
        $ip56 = "65.20.107.145"
        $ip57 = "65.20.99.10"

    condition:
        any of them
}

rule APT_VICESOCIETY {
    meta:
        description = "Indicators associated with APT VICESOCIETY"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "PolyVice, RedAlert, Chily"

    strings:
        $domain0 = "4hzyuotli6maqa4u.onion" nocase
        $domain1 = "fuckcisanet5nzv4d766izugxhnqqgiyllzfynyb4whzbqhzjojbn7id.onion" nocase
        $domain2 = "fuckfbrlvtibsdw5rxtfjxtog6dfgpz62ewoc2rpor2s6zd5nog4zxad.onion" nocase
        $domain3 = "ml3mjpuhnmse4kjij7ggupenw34755y4uj7t742qf7jg5impt5ulhkid.onion" nocase
        $domain4 = "vsociethok6sbprvevl4dlwbqrzyhxcxaqpvcqt5belwvsuxaxsutyad.onion" nocase
        $domain5 = "vsocietyjynbgmz4n4lietzmqrg2tab4roxwd2c2btufdwxi6v2pptyd.onion" nocase
        $domain6 = "wjdgz3btk257obba7aekowz7ylm33zb6hu4aetxc3bypfajixzvx4iad.onion" nocase
        $domain7 = "wmp2rvrkecyx72i3x7ejhyd3yr6fn5uqo7wfus7cz7qnwr6uzhcbrwad.onion" nocase

    condition:
        any of them
}

rule APT_VICIOUSPANDA {
    meta:
        description = "Indicators associated with APT VICIOUSPANDA"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "byeby, microcin, mikroceen"

    strings:
        $domain0 = "612bb.sheetsbrandnewday.com" nocase
        $domain1 = "9hnvb8917gzr.com" nocase
        $domain2 = "adyboh.com" nocase
        $domain3 = "ans.moutw.com" nocase
        $domain4 = "apjgtipty.com" nocase
        $domain5 = "app.obokay.com" nocase
        $domain6 = "apps.uzdarakchi.com" nocase
        $domain7 = "bestrongerlouder.com" nocase
        $domain8 = "bmy.hqoohoa.com" nocase
        $domain9 = "bur.vueleslie.com" nocase
        $domain10 = "bzz.utakatarefrain.com" nocase
        $domain11 = "cloud.googleupdating.net" nocase
        $domain12 = "cloud.msseces.com" nocase
        $domain13 = "cloud.systemupdating.com" nocase
        $domain14 = "clouds.googleupdating.net" nocase
        $domain15 = "clouds.osppsvc.com" nocase
        $domain16 = "compdate.my03.com" nocase
        $domain17 = "credibusco.com" nocase
        $domain18 = "dnsrequery.com" nocase
        $domain19 = "dw.adyboh.com" nocase
        $domain20 = "esvnpe.com" nocase
        $domain21 = "feb.kkooppt.com" nocase
        $domain22 = "forum.mediaok.info" nocase
        $domain23 = "forum.uzdarakchi.com" nocase
        $domain24 = "future-hope2011.com" nocase
        $domain25 = "googleupdating.net" nocase
        $domain26 = "heroisshit.com" nocase
        $domain27 = "hqoohoa.com" nocase
        $domain28 = "jocoly.esvnpe.com" nocase
        $domain29 = "kkooppt.com" nocase
        $domain30 = "kliju.wulinon.com" nocase
        $domain31 = "log.bestrongerlouder.com" nocase
        $domain32 = "mediaok.info" nocase
        $domain33 = "moutw.com" nocase
        $domain34 = "msdtcupdate.com" nocase
        $domain35 = "nan.thanhale.com" nocase
        $domain36 = "ns.dnsrequery.com" nocase
        $domain37 = "obokay.com" nocase
        $domain38 = "offcialwrittencomplaint.com" nocase
        $domain39 = "owa.obokay.com" nocase
        $domain40 = "parked.wulinon.com" nocase
        $domain41 = "qrot.apjgtipty.com" nocase
        $domain42 = "runtime.heroisshit.com" nocase
        $domain43 = "sheetsbrandnewday.com" nocase
        $domain44 = "systemupdating.com" nocase
        $domain45 = "thanhale.com" nocase
        $domain46 = "update.heroisshit.com" nocase
        $domain47 = "utakatarefrain.com" nocase
        $domain48 = "uzdarakchi.com" nocase
        $domain49 = "vueleslie.com" nocase
        $domain50 = "wind.windmilldrops.com" nocase
        $domain51 = "windmilldrops.com" nocase
        $domain52 = "wulinon.com" nocase
        $domain53 = "wy.adyboh.com" nocase
        $domain54 = "yuemt.zzux.com" nocase
        $ip55 = "58.64.209.84"
        $ip56 = "58.64.209.84"

    condition:
        any of them
}

rule APT_VOIDARACHNE {
    meta:
        description = "Indicators associated with APT VOIDARACHNE"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "103.214.146.34new.webcamcn.xyz" nocase
        $domain1 = "103.214.147.101.webcamcn.xyz" nocase
        $domain2 = "103.214.147.14.webcamcn.xyz" nocase
        $domain3 = "11.webcamcn.xyz" nocase
        $domain4 = "11new.webcamcn.xyz" nocase
        $domain5 = "156.248.54.11.webcamcn.xyz" nocase
        $domain6 = "156.248.54.11new.webcamcn.xyz" nocase
        $domain7 = "248.54.11.webcamcn.xyz" nocase
        $domain8 = "248.54.11new.webcamcn.xyz" nocase
        $domain9 = "54.11.webcamcn.xyz" nocase
        $domain10 = "54.11new.webcamcn.xyz" nocase
        $domain11 = "98.159.98.114.webcamcn.xyz" nocase
        $domain12 = "hm.webcamcn.xyz" nocase
        $domain13 = "hm2.webcamcn.xyz" nocase
        $domain14 = "hm3.webcamcn.xyz" nocase
        $domain15 = "hm4.webcamcn.xyz" nocase
        $domain16 = "hm6.webcamcn.xyz" nocase
        $domain17 = "hm9.webcamcn.xyz" nocase
        $domain18 = "webcamcn.xyz" nocase

    condition:
        any of them
}

rule APT_VOIDBLIZZARD {
    meta:
        description = "Indicators associated with APT VOIDBLIZZARD"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "laundry bear, void blizzard, pluggyape"

    strings:
        $domain0 = "aoc-gov.us" nocase
        $domain1 = "app-v4-mybos.com" nocase
        $domain2 = "avsgroup.au" nocase
        $domain3 = "bidscale.net" nocase
        $domain4 = "defraudatubanco.com" nocase
        $domain5 = "deloittesharepoint.com" nocase
        $domain6 = "ebsum.eu" nocase
        $domain7 = "ebsumlts.eu" nocase
        $domain8 = "ebsummlt.eu" nocase
        $domain9 = "ebsummt.eu" nocase
        $domain10 = "ebsumrnit.eu" nocase
        $domain11 = "ebsurnmit.eu" nocase
        $domain12 = "enticator-secure.com" nocase
        $domain13 = "gertasd.top" nocase
        $domain14 = "hart-hulp-ua.com" nocase
        $domain15 = "harthulp-ua.com" nocase
        $domain16 = "it-sharepoint.com" nocase
        $domain17 = "m-365-app.com" nocase
        $domain18 = "maidservant.shop" nocase
        $domain19 = "mail-forgot.com" nocase
        $domain20 = "max-linear.com" nocase
        $domain21 = "microffice.org" nocase
        $domain22 = "micsrosoftonline.com" nocase
        $domain23 = "miscrsosoft.com" nocase
        $domain24 = "myspringbank.com" nocase
        $domain25 = "ourbelovedsainscore.space" nocase
        $domain26 = "outlook-office.micsrosoftonline.com" nocase
        $domain27 = "portal-microsoftonline.com" nocase
        $domain28 = "propescom.com" nocase
        $domain29 = "redronesolutions.cloud" nocase
        $domain30 = "refundes.net" nocase
        $domain31 = "remerelli.com" nocase
        $domain32 = "saint-daniel.com" nocase
        $domain33 = "saint-daniel.org" nocase
        $domain34 = "saint-daniel.world" nocase
        $domain35 = "solidarity-help.com" nocase
        $domain36 = "solidarity-help.org" nocase
        $domain37 = "spidergov.org" nocase
        $domain38 = "teamsupportonline.top" nocase
        $domain39 = "weblogmail.live" nocase
        $domain40 = "x9a7lm02kqaccountprotectionaccountsecuritynoreply.com" nocase
        $ip41 = "108.165.164.155"
        $ip42 = "176.9.23.216"
        $ip43 = "193.23.216.39"
        $ip44 = "193.23.216.39"

    condition:
        any of them
}

rule APT_VOLATILECEDAR {
    meta:
        description = "Indicators associated with APT VOLATILECEDAR"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "DeftTorero, LebaneseCedar, VolatileCedar"

    strings:
        $domain0 = "carima2012.site90.com" nocase
        $domain1 = "dotnetexplorer.info" nocase
        $domain2 = "dotntexplorere.info" nocase
        $domain3 = "erdotntexplore.info" nocase
        $domain4 = "explorerdotnt.info" nocase
        $domain5 = "saveweb.wink.ws" nocase
        $domain6 = "xploreredotnet.info" nocase
        $ip7 = "200.159.87.196"

    condition:
        any of them
}

rule APT_WEAKESTLINK {
    meta:
        description = "Indicators associated with APT WEAKESTLINK"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "androidbak.com" nocase
        $domain1 = "droidback.com" nocase
        $domain2 = "endpointup.com" nocase
        $domain3 = "goodydaddy.com" nocase
        $domain4 = "siteanalysto.com" nocase

    condition:
        any of them
}

rule APT_WEBKY {
    meta:
        description = "Indicators associated with APT WEBKY"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "glb.it-desktop.com" nocase
        $domain1 = "globalprint-us.com" nocase
        $domain2 = "hi.getgo2.com" nocase
        $domain3 = "intranetwabcam.com" nocase
        $domain4 = "local.it-desktop.com" nocase
        $domain5 = "login.access-mail.com" nocase
        $domain6 = "ns1.logitech-usa.com" nocase

    condition:
        any of them
}

rule APT_WHITECOMPANY {
    meta:
        description = "Indicators associated with APT WHITECOMPANY"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "userz.ignorelist.com" nocase

    condition:
        any of them
}

rule APT_WICKEDPANDA {
    meta:
        description = "Indicators associated with APT WICKEDPANDA"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "money.moneyhome.biz" nocase
        $domain1 = "voda.dns04.com" nocase

    condition:
        any of them
}

rule APT_WINDSHIFT {
    meta:
        description = "Indicators associated with APT WINDSHIFT"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "domforworld.com" nocase
        $domain1 = "flux2key.com" nocase
        $domain2 = "string2me.com" nocase

    condition:
        any of them
}

rule APT_WINTERVIVERN {
    meta:
        description = "Indicators associated with APT WINTERVIVERN"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "sharpshooter, ta473"

    strings:
        $domain0 = "applicationdevsoc.com" nocase
        $domain1 = "bugiplaysec.com" nocase
        $domain2 = "centr-security.com" nocase
        $domain3 = "marakanas.com" nocase
        $domain4 = "nepalihemp.com" nocase
        $domain5 = "ocs-romastassec.com" nocase
        $domain6 = "ocsp-reloads.com" nocase
        $domain7 = "ocsp-report.com" nocase
        $domain8 = "ocspdep.com" nocase
        $domain9 = "oscp-avanguard.com" nocase
        $domain10 = "recsecas.com" nocase
        $domain11 = "secure-daddy.com" nocase
        $domain12 = "securemanage.com" nocase
        $domain13 = "securetourspd.com" nocase
        $domain14 = "security-ocsp.com" nocase
        $domain15 = "troadsecow.com" nocase

    condition:
        any of them
}

rule APT_WIRTE {
    meta:
        description = "Indicators associated with APT WIRTE"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "ashenloader, ashtag, ashenorchestrator"

    strings:
        $domain0 = "account.techupinfo.com" nocase
        $domain1 = "allaccounting.ca" nocase
        $domain2 = "api.healthylifefeed.com" nocase
        $domain3 = "api.medicinefinders.com" nocase
        $domain4 = "api.softmatictech.com" nocase
        $domain5 = "api.systemsync.info" nocase
        $domain6 = "api.technology-system.com" nocase
        $domain7 = "api.widetechno.info" nocase
        $domain8 = "apiv2.onlinefieldtech.com" nocase
        $domain9 = "auth.onlinefieldtech.com" nocase
        $domain10 = "bankjordan.com" nocase
        $domain11 = "cdn.techpointinfo.com" nocase
        $domain12 = "check.office365-update.com" nocase
        $domain13 = "dentalaccord.com" nocase
        $domain14 = "dentalmatrix.net" nocase
        $domain15 = "doctoressolis.com" nocase
        $domain16 = "download.share2file.pro" nocase
        $domain17 = "easybackupcloud.com" nocase
        $domain18 = "economymentor.com" nocase
        $domain19 = "economystocking.com" nocase
        $domain20 = "eg.foxlove.life" nocase
        $domain21 = "egyptican.com" nocase
        $domain22 = "egyptskytours.com" nocase
        $domain23 = "egypttourism-online.com" nocase
        $domain24 = "ellemedic.com" nocase
        $domain25 = "est-clinic.com" nocase
        $domain26 = "finance-analyst.com" nocase
        $domain27 = "financecovers.com" nocase
        $domain28 = "financeinfoguide.com" nocase
        $domain29 = "firstohiobank.com" nocase
        $domain30 = "forum.technoforts.com" nocase
        $domain31 = "forum.techtg.com" nocase
        $domain32 = "fox.foxlove.life" nocase
        $domain33 = "foxlove.life" nocase
        $domain34 = "healthcarb.com" nocase
        $domain35 = "healthoptionstoday.com" nocase
        $domain36 = "healthscratches.com" nocase
        $domain37 = "healthylifefeed.com" nocase
        $domain38 = "imagine-world.com" nocase
        $domain39 = "jo.foxlove.life" nocase
        $domain40 = "jordanrefugees.com" nocase
        $domain41 = "jordansons.com" nocase
        $domain42 = "king-pharmacy.com" nocase
        $domain43 = "kneeexercises.net" nocase
        $domain44 = "master-dental.com" nocase
        $domain45 = "medicinefinders.com" nocase
        $domain46 = "micorsoft.store" nocase
        $domain47 = "microsoftliveforums.com" nocase
        $domain48 = "microsoftteams365.com" nocase
        $domain49 = "microsoftwindowshelp.com" nocase
        $domain50 = "neweconomysolution.com" nocase
        $domain51 = "niftybuysellchart.com" nocase
        $domain52 = "nutrition-information.org" nocase
        $domain53 = "office-update.services" nocase
        $domain54 = "office365-update.co" nocase
        $domain55 = "office365-update.com" nocase
        $domain56 = "omegaeyehospital.com" nocase
        $domain57 = "onlinefieldtech.com" nocase
        $domain58 = "pocket-property.com" nocase
        $domain59 = "printspoolerupdates.com" nocase
        $domain60 = "qrdorks.com" nocase
        $domain61 = "saudiarabianow.org" nocase
        $domain62 = "saudiday.org" nocase
        $domain63 = "share2file.pro" nocase
        $domain64 = "softmatictech.com" nocase
        $domain65 = "status.techupinfo.com" nocase
        $domain66 = "stgeorgebankers.com" nocase
        $domain67 = "sun-tourist.com" nocase
        $domain68 = "suppertools.com" nocase
        $domain69 = "support-api.financecovers.com" nocase
        $domain70 = "systemsync.info" nocase
        $domain71 = "technoforts.com" nocase
        $domain72 = "techpointinfo.com" nocase
        $domain73 = "techtg.com" nocase
        $domain74 = "techupinfo.com" nocase
        $domain75 = "thefinanceinvest.com" nocase
        $domain76 = "theshortner.com" nocase
        $domain77 = "trendingcharts.finance-analyst.com" nocase
        $domain78 = "unitedfamilyhealth.net" nocase
        $domain79 = "update.share2file.pro" nocase
        $domain80 = "wellhealthtech.com" nocase
        $domain81 = "widetechno.info" nocase
        $ip82 = "104.24.108.64"
        $ip83 = "104.24.109.64"
        $ip84 = "104.28.1.134"
        $ip85 = "172.86.75.211"
        $ip86 = "185.86.79.243"
        $ip87 = "194.38.11.3"

    condition:
        any of them
}

rule APT_WUQIONGDONG {
    meta:
        description = "Indicators associated with APT WUQIONGDONG"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "apt-c-59, apt-q-11, shadowtiger"

    strings:
        $domain0 = "blue.chinfoset.com" nocase
        $domain1 = "cchiwa.com" nocase
        $domain2 = "chinfoset.com" nocase
        $domain3 = "cloud.unite.un.org.docs-verify.com" nocase
        $domain4 = "common.js.ftp.sh" nocase
        $domain5 = "data.cchiwa.com" nocase
        $domain6 = "datasectioninfo.com" nocase
        $domain7 = "docs-verify.com" nocase
        $domain8 = "guest-mailclouds.com" nocase
        $domain9 = "hao.360.mooo.com" nocase
        $domain10 = "helpdesk-mailservice.com" nocase
        $domain11 = "itoxtlthpw.com" nocase
        $domain12 = "lion.waitnetwork.net" nocase
        $domain13 = "mail-drivecenter.com" nocase
        $domain14 = "mail-hostfile.com" nocase
        $domain15 = "mail.datasectioninfo.com" nocase
        $domain16 = "microsoft.ccivde.com" nocase
        $domain17 = "morning-place.com" nocase
        $domain18 = "ms0ffice.guest-mailclouds.com" nocase
        $domain19 = "netease.mail-drivecenter.com" nocase
        $domain20 = "netease.smartsystem36.com" nocase
        $domain21 = "oversea-cnki.net" nocase
        $domain22 = "service-hq.com" nocase
        $domain23 = "smartsystem36.com" nocase
        $domain24 = "waitnetwork.net" nocase
        $ip25 = "37.120.140.233"
        $ip26 = "62.112.8.79"
        $ip27 = "66.70.220.100"
        $ip28 = "88.150.227.110"

    condition:
        any of them
}

rule APT_XDSPY {
    meta:
        description = "Indicators associated with APT XDSPY"
        author = "APTtrail"
        date = "auto-generated"
        aliases = "xdigo"

    strings:
        $domain0 = "365downloading.com" nocase
        $domain1 = "aoc-upravleniye.com" nocase
        $domain2 = "best-downloader.com" nocase
        $domain3 = "boborux.com" nocase
        $domain4 = "bukhgalter-x5group.com" nocase
        $domain5 = "bystryvelosiped.com" nocase
        $domain6 = "cellporyad.com" nocase
        $domain7 = "chistyyvozdukh.com" nocase
        $domain8 = "chtcc.net" nocase
        $domain9 = "cracratutu.com" nocase
        $domain10 = "daftsync.com" nocase
        $domain11 = "documentsklad.com" nocase
        $domain12 = "doverennyye-fayly.com" nocase
        $domain13 = "download-365.com" nocase
        $domain14 = "download24center.com" nocase
        $domain15 = "downloading24.com" nocase
        $domain16 = "downloadsprimary.com" nocase
        $domain17 = "dropsklad.com" nocase
        $domain18 = "dversteklo.com" nocase
        $domain19 = "dwd765m.com" nocase
        $domain20 = "easy-download24.com" nocase
        $domain21 = "easytosay.org" nocase
        $domain22 = "fakturaaa.com" nocase
        $domain23 = "faylbox365.com" nocase
        $domain24 = "faylsklad.com" nocase
        $domain25 = "ferrariframework.com" nocase
        $domain26 = "file-bazar.com" nocase
        $domain27 = "file-download.org" nocase
        $domain28 = "file-magazin.com" nocase
        $domain29 = "filedownload.email" nocase
        $domain30 = "full-downloader.com" nocase
        $domain31 = "getthatupdate.com" nocase
        $domain32 = "global-downloader.com" nocase
        $domain33 = "jerseygameengine.com" nocase
        $domain34 = "just-downloads.com" nocase
        $domain35 = "khitrayalisitsa.com" nocase
        $domain36 = "khoroshayamych.com" nocase
        $domain37 = "kletchatayarubashka.com" nocase
        $domain38 = "krasnayastena.com" nocase
        $domain39 = "laultrachunk.com" nocase
        $domain40 = "magnitgroup.com" nocase
        $domain41 = "maiwegwurst.com" nocase
        $domain42 = "melodicprogress.com" nocase
        $domain43 = "migration-info.com" nocase
        $domain44 = "minisnowhair.com" nocase
        $domain45 = "moy-fayl.com" nocase
        $domain46 = "moy-pdf.com" nocase
        $domain47 = "my1businessconnection.com" nocase
        $domain48 = "nevynosimayapchela.com" nocase
        $domain49 = "nniir.com" nocase
        $domain50 = "nomatterwhat.info" nocase
        $domain51 = "obmen-faylami.com" nocase
        $domain52 = "officeupdtcentr.com" nocase
        $domain53 = "otpravkafaylov.com" nocase
        $domain54 = "pdf-bazaar.com" nocase
        $domain55 = "pdf-reyestr.com" nocase
        $domain56 = "pdf-sklad.com" nocase
        $domain57 = "pdfdepozit.com" nocase
        $domain58 = "pdfmagazin.com" nocase
        $domain59 = "pdfsklad.com" nocase
        $domain60 = "pechalnoyebudushcheye.com" nocase
        $domain61 = "promenimath.com" nocase
        $domain62 = "protej.org.nniir.com" nocase
        $domain63 = "quan-miami.com" nocase
        $domain64 = "reyestr-faylov.com" nocase
        $domain65 = "ru-pochta365.com" nocase
        $domain66 = "ru-sistema.com" nocase
        $domain67 = "sbordokumentov.com" nocase
        $domain68 = "seatwowave.com" nocase
        $domain69 = "serayagrust.com" nocase
        $domain70 = "seychaspozzhe.com" nocase
        $domain71 = "skachivanie-failov.com" nocase
        $domain72 = "skachivanie-failov24.com" nocase
        $domain73 = "slomannyymonitor.com" nocase
        $domain74 = "sogrevayushchiynapitok.com" nocase
        $domain75 = "svobodnoepredlozheniye.com" nocase
        $domain76 = "temnayamashina.com" nocase
        $domain77 = "theslideshare.com" nocase
        $domain78 = "trxpay.cc" nocase
        $domain79 = "tvoi-fayly.com" nocase
        $domain80 = "tvoy-disk.com" nocase
        $domain81 = "utrenneyesolntse.com" nocase
        $domain82 = "vash-disk.com" nocase
        $domain83 = "vashazagruzka365.com" nocase
        $domain84 = "vashi-fayly.com" nocase
        $domain85 = "wildboarcontest.com" nocase
        $domain86 = "zagruzka-pdf.com" nocase
        $domain87 = "zagruzkadannykh.com" nocase
        $domain88 = "zagruzkafayla.com" nocase
        $domain89 = "zelenyysalat.com" nocase
        $domain90 = "zetta-strakhovaniye.com" nocase
        $domain91 = "zhestovyyliker.com" nocase
        $domain92 = "zimniyeravlecheniya.com" nocase

    condition:
        any of them
}

rule APT_XPATH {
    meta:
        description = "Indicators associated with APT XPATH"
        author = "APTtrail"
        date = "auto-generated"

    strings:
        $domain0 = "dns03.cainformations.com" nocase
        $domain1 = "kkkfaster.jumpingcrab.com" nocase
        $domain2 = "nicodonald.accesscam.org" nocase
        $domain3 = "pneword.net" nocase
        $domain4 = "sultris.com" nocase
        $domain5 = "tv.teldcomtv.com" nocase
        $domain6 = "v.nnncity.xyz" nocase

    condition:
        any of them
}

